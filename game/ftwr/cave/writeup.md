# Follow the white Rabbit - Cave

For this challenge we are given a zip in which we can find a Game Executable and some Data and Libraries for it.

As I had no idea what the game is and what our goal is, I just played the game for a bit.
## Exploration

We are in an open world game and like the title suggests we have to follow the white Rabbit. So that's what I did, but there were a few difficulties connected to that.

There a 2 paths that we can take. This challenge was about taking the first path down a very deep hole. Sadly if we arrive down at the bottom we die from fall damage (Or that's what I assume, there is no health bar or other indicator).  

So our goal is to somehow survive that fall or teleport down there or something like that.

I did not want to open a disassembler and edit the code just yet, so I tried a few things that could trick the game into letting me survive.

First of all I recognize, that we can survive smaller falls so I assumed, that the game tracks how long we have been falling for.
So I jumped down the hole and just before I hit the ground I paused the game. My hope was, that the game would reset the variables which count how long I have been falling for, if I pause it. But sadly that did not work.

The second thing I did was to press ever key on my keyboard once and try to find hidden features, because there were no controls setting where I could look up  
everything I can do. And I actually found something besides the usual WASD keys and the shift for sprint. F1 triggered my death without doing anything besides that and F2 would bring up some kind of debug screen.

Obviously I was more interested in the F1 key. It could kill you if you are alive and could revive you if you were dead. So I jumped down the hole and tried to revive me after I died. It actually worked: the "Noob." death screen disappeared, but I had no control over my character anymore.

After that I had no idea anymore so I had to look into how the game works.
## Disassembling

The loading screen of the game showed the Unity logo so I assumed it uses the Unity game engine. I also noticed the "MonoBleedingEdge" folder in the downloaded zip. So I quickly goggled "Mono Unity" and found out, that Mono is similar to .NET (I'm new to Windows game hacking and Windows in general, so what I say might not be totally correct, but this is how I understand it). I knew of "dnSpy" a disassembler for the .NET Framework so I searched for an equivalent for Mono ... and found "ILSpy". It can decompile the Mono intermediate code into readable C#. From a [video](https://www.youtube.com/watch?v=r7tywn0QMqo) I even found out, how to modify the Code using a plugin called Reflexil.

## Editing the code

![](https://raw.githubusercontent.com/Nayos1337/cscg2020/master/game/ftwr/cave/img1.png)

After looking through the classes in the "Assemby-CSharp.dll" Library a bit I found an interesting one : Player Controller.
It contains a Method called "CheckFallDeath".
```csharp
// PlayerController
private void CheckFallDeath()
{
	if (m_IsGrounded && m_VerticalSpeed < 0f - (maxGravity - 0.1f))
	{
		Die();
	}
}
```
With the help of the Reflexil plug-in I nopped out that function and jumped into the game again.

![](https://raw.githubusercontent.com/Nayos1337/cscg2020/master/game/ftwr/cave/img2.png)
