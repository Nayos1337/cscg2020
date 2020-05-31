# Staywoke shop

This challenge was a Web challenge of the CSCG 2020.
If we visit the website we are granted with a very funny looking shopping site. We can buy 5 different items for 1€ each. Each of these products link to `http://staywoke.hax1.allesctf.net/products/X` where `X` is a number from 2 - 6. There is no link to product 1, so of cause I tried it and we get to the product page for the flag. It costs 1337€! If we try to check out we can enter a promo code and we have to enter a payment method (w0kecoin / Desinfektionsmittel (eng: Disinfectants)) and an account id. As I had no idea I just choose  `w0kecoin` and entered a random account id. But we get the error message `Wallet balance too low!`. So we somehow need to find a valid Wallet. The thing I did next was to open the [Burp HTTP-Proxy](https://portswigger.net/burp) to monitor the requests made by the browser.
If we try to checkout we do this request :
```
POST /checkout HTTP/1.1
Host: staywoke.hax1.allesctf.net
Content-Length: 77
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://staywoke.hax1.allesctf.net
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.138 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Referer: http://staywoke.hax1.allesctf.net/checkout
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Cookie: session=s%3A6viNsVVHzuZyVmUQrNJm4M37Morj45yK.1I3JQ91isMWCifAIowq%2FPLuXx7QV05JPbTGnoYhTh0k
Connection: close

payment=w0kecoin&account=1337&paymentEndpoint=http%3A%2F%2Fpayment-api%3A9090
```
The interesting thing about this is the `paymentEndpoint` parameter. I send the request to the Repeater and tried a few things.
Here is what I found out:
* If we try to reach any address besides `paymet-api` (even localhost) we get a DNS Error => no outside requests
* The only supported protocol is `http`

As there is no other host besides the `paymet-api`, I tried some things there:
The application probably appends something to our param, so I choose:
`http://payment-api:9090?x=`. It  ignores everything appended because it is now the `x` get parameter. From the request we get `Error from Payment API: "Cannot GET /\n\nTry GETting /help for possible endpoints."` Which is clearly a hint so I tried : `http://payment-api:9090/help?x=`
Resulting in:
```json
{
    "endpoints": [
        {
            "method": "GET",
            "path": "/wallets/:id/balance",
            "description": "check wallet balance"
        },
        {
            "method": "GET",
            "path": "/wallets",
            "description": "list all wallets"
        },
        {
            "method": "GET",
            "path": "/help",
            "description": "this help message"
        }
    ]
}
```
We want to find valid wallets: `http://payment-api:9090/wallets?x=`
```json
[{"account":"1337-420-69-93dcbbcd","balance":133500}]
```
There we have got a valid wallet and it also has a lot of money, but if we try to buy the flag, we still get the `Wallet balance too low!` error. That was weird, so I tried to buy and item which only costs 1€ and that worked.
I concluded from that, that the balance is in cents. That means we have to somehow spare 2€. Because I had no idea how we can this I just looked around a bit more.
Eventually I saw the banner in the site saying: `20% Rabatt mit dem Code I<3CORONA` (`20% discount with the code I<3CORONA`). 20% is more than enough so I tried using that code, but it didn't work. Yet again it would work for items costing less than the flag. After that I checked my cart again and realized, that the code was actually added as a new Item to the card, which meant I could remove the other items and have the cart cost -0,20€. The Idea now was to add a lot of products to the cart and than use the code. After that I would remove the added Items resulting in a cart that is worth -2€. To the cart we could than add the flag and pay for it with our found wallet. And this actually works! There is a limit of 10 items we can put into the cart, but this is just enough for a discount of 2€.
`CSCG{c00l_k1ds_st4y_@_/home/}`
