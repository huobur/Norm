# .NET Fans out there? I'm Norm

There are basically two flavors of .NET:

1. .NET Framework - this is for Microsoft Windows platform only. The latest version is v4.8 [1]
2. .NET Core - this is a cross-platform technology to be run on Windows, Mac, Linux and others. The latest version is v3.1 [2]

Microsoft is also working very hard to unify them both to a holy grail .NET called .NET 5 which will be released later this year (to avoid the confusion with .NET Framework 4.x, Microsoft decided to move from .NET Core 3.1 directly to .NET 5. In .NET 5, the word "Core" is removed as it also covers .NET Framework and the .NET Framework will be gratually phased out once .NET 5 is released)

On May 19th, Microsoft released .NET 5 Preview SDK 5.0.0-preview.4 [3]. 

![.NET5](dotnet5_platform.png)

In order for a program to work on various platforms, there has to be a layer of abstrction such that all platform differences can be isolated from above programming languages and functional framework and applications. This layer is called "CLR" - Common Language Runtime in .NET world. The program running in this environment is called "Managed Code". Without this layer, we write program to directly run on an OS platform, which is called "Native Code".

In this article, we are going to work on a project to detect if a program is <b>N</b>ative <b>or</b> <b>M</b>anaged code, hence "Norm" is born.

## Setup .NET Environment and Create .NET Projects

1. Install .NET 5 on both Windows 10 and WSL

To have more fun to explore .NET technologies and some transitional nuances, we'll install .NET 5.0 v5.0.0-preview.4 on both Windows 10 and WSL (with Ubuntu 19.04 installed on my machine, you should check with .NET 5 info to see if your is supported or not if you'd like to try .NET 5 on Linux) on the same machine. 

Please download .NET 5.0 SDK 5.0.100-preview.4 from the reference [3] and install them on Windows 10 (Windows, Installers, x64), and WSL (Linux, Binaries, x64). (if anyone has issues, please leave a message, I'm pretty sure that someone or I can help.)

On Windows, if you check on command line, you should see:
```
c:\dotnet --version
5.0.100-preview.4.20258.7
```

On WSL, similarly you should be able to see the exactly the same version number:
```
$ dotnet --version
5.0.100-preview.4.20258.7
```

2. Create Two Skeleton Projects

On your Windows 10 machine, first create a directory c:\projects, and then create a new project "norm" and run it:
```
c:\projects\dotnet new console -n norm
c:\projects\cd norm
c:\projects\norm\dotnet run
Hello World!
```

From WSL, navigate to c:\projects directory: (WSL Ubuntu can access Windows file systems directly)
```
$cd /mnt/c/projects
```
Create a new project "normwsl" and run it:
```
/mnt/c/projects$dotnet new console -n normwsl
/mnt/c/projects$cd normwsl
/mnt/c/projects/normwsl$dotnet run
Hello World!
```

3. Engineering notes:

* What we have done in WSL system can be replicated on an independent Linux machine, we use WSL only for convenient purposes;
* When we create a .NET console project, in the project folder, it generates two files and one directory: "Program.cs" and "*.csproj" files and an "obj" directory. 
* The contents of the two project files in Windows and WSL are identical:

```
<Project Sdk="Microsoft.NET.Sdk">

  <PropertyGroup>
    <OutputType>Exe</OutputType>
    <TargetFramework>net5.0</TargetFramework>
  </PropertyGroup>

</Project>
```
* Let's inspect what is in the "obj" directory: there are two "*.json" files, each of them has a section of following content:
```
      "frameworks": {
        "net5.0": {
          "imports": [
            "net461",
            "net462",
            "net47",
            "net471",
            "net472",
            "net48"
          ],
```
This may give us an suspecion that .NET 5 is not only supports .NET Core, but also supports .NET Frameworks. And it's indeed confirmed that I just replaced "net5.0" in the project file to each one of the above 7 .NET Framework versions, I could build a specific .NET Framework executable successfully. So, we know that at least the current .NET 5 preview release will support the 7 versions of .NET Frameworks. This could change from time to time.

## Project Norm Design

With all of the above preparation, we can now get into our project design and coding.

Let's take a look our main design objectives:

1. On a Windows system, it checks both "*.exe" and "*.dll" files to determine two things:

* if it's written in Native or Managed code;
* If it's a 32 bit or 64 bit code;

2. This is a console program, a user can also feed input from the commandline by providing either a file name or directory name such that Norm will conduct the check and output the findings. By default, if there is no argument provided, the program will check from it's launching directory and its subdirectories and output the results.

The program itself is really not that complicated, and it contains just one class in one namespace:

```
namespace NativeOrManaged
{
    public class NativeOrManaged {
        ......

    }
}
```

There are 4 functions in the class:

```
static void Main(string[] args) { ... }
```

This function is the program entry point and takes 0 or 1 input parameters. If a file name is provideded, the program will only check this one file and provides output; Otherwise, it will traverse a directory provided and its subdirectories to output findings. If no input parameter is provided, it'll just check the program launching directory and its subdirectories.

Here we also provide a usage help info when the user either provides "/?" or "-h".

If everything checks ok, Main() will call TraveerseTree() to further process with file/directory info pass along. 

```
public static void TraverseTree(string dorf) { ... }
```

The TraverseTree() will be passed in either a file name (from input) or directory name (from input or by default). It then traverses through all directories and files in them to find out info and collect it, and eventually output when done.

It calls the two functions to process file details:

```

public static bool DesiredFileType(string file) { ... }
```

This is a filter function to simply identify .exe and .dll files as they are the executables on Windows machine.

```

static void GetPEInfo(string fileName) { ... }

```

This is the gut of the program. It follows through [5],[6] to find detail info on what we originally planned in our design:
1. First we check the DOS signature, yes, the DOS signature. I know it goes back quite some years, but there is nothing we can do but inheirate for backwards compatibility through all past Microsoft years;

2. We check PE signatures to make sure the file is in right format;

3. We read through COFF (Common Object File Format) header; The info on if it's 32-bit code or 64 bit code is stored here and we'll remember it for final process later.

4. Process PE Optional Header to find out if it's PE or PE+ format.

5. Read 16 data directories; And the CLR info is at the 15th location.

6. Now, we know the CLR bit in the step 5 (it tells if the code is managed or native), and also if it's 32-bit or 64-bit from the step 3. And finally we have all info we need for an executable file processed.  

The whole source code can be downloaded from [7].

## Build and Run Norm!

Please download the code and replace it be the Program.cs file both in 
```
c:\projects\norm\Program.cs
/mnt/c/projects/normwsl/Program.cs
```

go head and build it and run it:
```
c:\projects\norm\dotnet run 
/mnt/c/projects/normwsl$dotnet run
```

Do you get any output? If you do, how cool is that? Especially you have to realize that you are running a .Net program from Linux and you can even check Windows file system, give it a try by running the following:
```
/mnt/c/projects/normwsl$dotnet run /mnt/c/Windows
```

Of cause, it's the same if you run within the Windows system:
```
c:\projects\norm\dotnet run c:\Windows
```

As we have discussed earlier, you can also build .NET Framework version of the program by modifying both norm.csproj and normwsl.csproj:
```
<Project Sdk="Microsoft.NET.Sdk">

  <PropertyGroup>
    <OutputType>Exe</OutputType>
    <TargetFramework>net48</TargetFramework>
  </PropertyGroup>

</Project>
```

There are a lot of things to do and think. As this short article is getting long, I'll leave some homework for you to further explore.

## Homework
* If you have Visual Studio installed, you can simply run:
```
csc program.c
```
to play with it.
* Why does .NET separate a program into executable and dlls?
* Why does Windows .NET 5 build work on Linux, but not the other way around? (hint, use "file" utility)
* How to build a project into one single executable?
* Install .NET 5 on a separate Linux machine to see how much is true with our tests?
* What about on an ARM Linux?
* ...


# References

[1] https://dotnet.microsoft.com/download/dotnet-framework

[2] https://dotnet.microsoft.com/download/dotnet-core/3.1

[3] https://dotnet.microsoft.com/download/dotnet/5.0

[4] https://devblogs.microsoft.com/dotnet/introducing-net-5/

[5] https://docs.microsoft.com/en-us/dotnet/standard/assembly/file-format

[6] https://en.wikipedia.org/wiki/Portable_Executable

[7] https://github.com/huobur/Norm

