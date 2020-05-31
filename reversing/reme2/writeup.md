# ReMe 2

This is one of the reversing challenges.
We are given:
* ReMe.dll
* ReMe.deps.json
* ReMe.runtimeconfig.json

In this binary we can find two flags. We already got the first one: `CSCG{CanIHazFlag?}`. The second one is a bit more complex to get.
Again we look at the binary using [dnSpy](https://github.com/0xd4d/dnSpy)
```csharp
private static void Main(string[] args)
{
	Program.InitialCheck(args);
	byte[] ilasByteArray = typeof(Program).GetMethod("InitialCheck", BindingFlags.Static | BindingFlags.NonPublic).GetMethodBody().GetILAsByteArray();
	byte[] array = File.ReadAllBytes(Assembly.GetExecutingAssembly().Location);
	int[] array2 = array.Locate(Encoding.ASCII.GetBytes("THIS_IS_CSCG_NOT_A_MALWARE!"));
	MemoryStream memoryStream = new MemoryStream(array);
	memoryStream.Seek((long)(array2[0] + Encoding.ASCII.GetBytes("THIS_IS_CSCG_NOT_A_MALWARE!").Length), SeekOrigin.Begin);
	byte[] array3 = new byte[memoryStream.Length - memoryStream.Position];
	memoryStream.Read(array3, 0, array3.Length);
	byte[] rawAssembly = Program.AES_Decrypt(array3, ilasByteArray);
	object obj = Assembly.Load(rawAssembly).GetTypes()[0].GetMethod("Check", BindingFlags.Static | BindingFlags.Public).Invoke(null, new object[]
	{
		args
	});
}
```

```csharp
private static void InitialCheck(string[] args)
{
	Program.Initialize();
	bool isAttached = Debugger.IsAttached;
	if (isAttached)
	{
		Console.WriteLine("Nope");
		Environment.Exit(-1);
	}
	bool flag = true;
	Program.CheckRemoteDebuggerPresent(Process.GetCurrentProcess().Handle, ref flag);
	bool flag2 = flag;
	if (flag2)
	{
		Console.WriteLine("Nope");
		Environment.Exit(-1);
	}
	bool flag3 = Program.IsDebuggerPresent();
	if (flag3)
	{
		Console.WriteLine("Nope");
		Environment.Exit(-1);
	}
	bool flag4 = args.Length == 0;
	if (flag4)
	{
		Console.WriteLine("Usage: ReMe.exe [password] [flag]");
		Environment.Exit(-1);
	}
	bool flag5 = args[0] != StringEncryption.Decrypt("D/T9XRgUcKDjgXEldEzeEsVjIcqUTl7047pPaw7DZ9I=");
	if (flag5)
	{
		Console.WriteLine("Nope");
		Environment.Exit(-1);
	}
	else
	{
		Console.WriteLine("There you go. Thats the first of the two flags! CSCG{{{0}}}", args[0]);
	}
	IntPtr moduleHandle = Program.GetModuleHandle("kernel32.dll");
	bool flag6 = moduleHandle != IntPtr.Zero;
	if (flag6)
	{
		IntPtr procAddress = Program.GetProcAddress(moduleHandle, "CheckRemoteDebuggerPresent");
		bool flag7 = Marshal.ReadByte(procAddress) == 233;
		if (flag7)
		{
			Console.WriteLine("Nope!");
			Environment.Exit(-1);
		}
	}
}
```

As I have no Idea how about C# and dotnet internals and the second part of the `Main` function looks very technical I'm  trying to get this binary debugged, but for this to work we need to bypass all the checks made in the `InitialCheck` function. Luckily `dnSpy` has an option to bypass the first few, but the last one is a bit tricky. We can step over the Program until we reach `Marshal.ReadByte(procAddress) == 233;`, there we can make a single step and right before we return we can change the returned value, to not be 233. And with that we have bypassed the check. After that we only need to Step trough the code until we reach the `Invoke` call in the Main function. There we can step into and look at the code being executed after that.
```csharp
public static void Check(string[] args)
{
	bool flag = args.Length <= 1;
	if (flag)
	{
		Console.WriteLine("Nope.");
	}
	else
	{
		string[] array = args[1].Split(new string[]
		{
			"_"
		}, StringSplitOptions.RemoveEmptyEntries);
		bool flag2 = array.Length != 8;
		if (flag2)
		{
			Console.WriteLine("Nope.");
		}
		else
		{
			bool flag3 = "CSCG{" + array[0] == "CSCG{n0w" && array[1] == "u" && array[2] == "know" && array[3] == "st4t1c" && array[4] == "and" && Inner.CalculateMD5Hash(array[5]).ToLower() == "b72f3bd391ba731a35708bfd8cd8a68f" && array[6] == "dotNet" && array[7] + "}" == "R3333}";
			if (flag3)
			{
				Console.WriteLine("Good job :)");
			}
		}
	}
}

// Token: 0x06000002 RID: 2 RVA: 0x0000215C File Offset: 0x0000035C
public static string CalculateMD5Hash(string input)
{
	MD5 md = MD5.Create();
	byte[] bytes = Encoding.ASCII.GetBytes(input);
	byte[] array = md.ComputeHash(bytes);
	StringBuilder stringBuilder = new StringBuilder();
	for (int i = 0; i < array.Length; i++)
	{
		stringBuilder.Append(array[i].ToString("X2"));
	}
	return stringBuilder.ToString();
}
```
This is now very trivial. The only thing we need to do is crack this md5 Hash. I used https://crackstation.net/, which got the result `dynamic`.
The whole second flag is therefor : `CSCG{n0w_u_know_st4t1c_and_dynamic_dotNet}`
