# ReMe 1

This is one of the reversing challenges.
We are given:
* ReMe.dll
* ReMe.deps.json
* ReMe.runtimeconfig.json

If we run `ReMe.dll` without any password we get:
```bash
$ dotnet.exe ReMe.dll                  
Usage: ReMe.exe [password] [flag]
```
There are two flags, this challenge is about finding the first one `[password]`. As this is a dotnet binary we can open it in [dlSpy.exe](https://github.com/0xd4d/dnSpy), a dotnet decompiler.

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

These are the only two functions important for the first flag.
`Main` calls `InitialCheck` the second function. This function does a few comparisons and checks weather or not a debugger is attached. After that it compares the first Argument passed to it (the first flag) with `StringEncryption.Decrypt("D/T9XRgUcKDjgXEldEzeEsVjIcqUTl7047pPaw7DZ9I=");`. And if these strings are equal we get the first success message. We can now simply copy the Code for `StringEncryption.Decrypt` and call `StringEncryption.Decrypt("D/T9XRgUcKDjgXEldEzeEsVjIcqUTl7047pPaw7DZ9I=");` in another project.
`CanIHazFlag?` is the result of that.

```bash
$ dotnet.exe ReMe.dll CanIHazFlag?
There you go. Thats the first of the two flags! CSCG{CanIHazFlag?}
```
