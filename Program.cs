//
// This Windows console program is to scan a given file or directory (. the launching directory by default) and its subdirectories to output 
// the file names of executables and dll modules with info on the file type of native or managed, and 32 bit or 64 bit
//
// Ping He 2020-05-25
// Appreciate the acknowledgement if the code is used in any format
// License: https://en.wikipedia.org/wiki/MIT_License

using System;
using System.IO;
using System.Collections.Generic;
using System.Collections.Specialized;


namespace NativeOrManaged
{
    public class NativeOrManaged
    {
        static StringCollection log = new StringCollection(); // log recording errors and exceptions

        static int total = 0; // Total number of executables found

        static void Main(string[] args)
        {
            // Default local directory if no parameter is provided.
            string[] inputs = { @"." };

            // Command line parameter is provided, we only take one input parameter or help options:
            // 1. A directory
            // 2. A file
            // 3. Invalid parameter
            // 4. No parameter
            if (args.Length > 0)
            {
                inputs = args;

                // Display help info
                if ((inputs[0] == @"/?") || (inputs[0] == @"-h"))
                {
                    Console.WriteLine(@" This program will search and process executable files to output: ");
                    Console.WriteLine(@" 1. Native or managed code;");
                    Console.WriteLine(@" 2. 64 bit or 32 bit code");
                    Console.WriteLine(@" Usage: NorM");
                    Console.WriteLine(@"        NorM  -h (or /?)");
                    Console.WriteLine(@"        NorM  <file name>");
                    Console.WriteLine(@"        NorM  <directory name>");

                    return;
                }
                else // other args
                {
                    TraverseTree(inputs[0]);
                }
            }
            else // no args
            {
                TraverseTree(inputs[0]);
            }
        }

        // Figure out if the file passed in is valid executable or not (exe and dll only)
        public static bool DesiredFileType(string file)
        {
            if (File.Exists(file))
            {
                if (file.ToLower().EndsWith(".exe") || file.ToLower().EndsWith(".dll"))
                {
                    return true;
                }
                else // Not the right file type we are looking for
                {
                    return false;
                }
            }
            else // Not a file
            {
                return false;
            }
        }

        // Travese the directory and its subdirectories
        // 1. The dorf passed in might be a file instead
        // 2. The dorf passed in might be invalid directory or bad parameter
        // 3. A valid directory (the launching directory or others)
        public static void TraverseTree(string dorf)
        {
            Stack<string> dirs = new Stack<string>(500);  // initiate with 500 subdirectories or make a change. 

            // Something bad is passed in
            if (!(File.Exists(dorf) || Directory.Exists(dorf)))
            {
                Console.WriteLine(@"The directory or file doesn't exist!");
                return;
            }

            // Check to see if it's file or directory
            if (File.Exists(dorf))   // We got a file passed directly from the command line
            {
                // Check the right file type (exe or dll)
                if (DesiredFileType(dorf)) // got it!
                {
                    GetPEInfo(dorf);
                }
                else // wrong file type
                {
                    Console.WriteLine(@"The file is not executable type (.exe or .dll)");
                }

                return; // we are done!
            }
            else // Check if it's a valid directory
            {
                if (!System.IO.Directory.Exists(dorf)) // bad dorf directory
                {
                    Console.WriteLine(@"The diretory is invalid!");
                }
                else // whew, finally found a valid dorf directory
                {
                    dirs.Push(dorf);
                }
            }

            // Let's find them all!
            while (dirs.Count > 0)
            {
                string currentDir = dirs.Pop();
                string[] subDirs;

                try
                {
                    subDirs = Directory.GetDirectories(currentDir);
                }
                // An UnauthorizedAccessException exception will be thrown 
				// if the directory access is not permitted. 
                catch (UnauthorizedAccessException e)
                {
                    log.Add(e.Message);
                    continue;
                }
                catch (System.IO.DirectoryNotFoundException e)
                {
                    log.Add(e.Message);
                    continue;
                }

                string[] files = null;

                try
                {
                    files = Directory.GetFiles(currentDir);
                }
                // An UnauthorizedAccessException exception will be thrown 
				// if the file access is not permitted. 
                catch (UnauthorizedAccessException e)
                {
                    Console.WriteLine(e.Message);
                    continue;
                }
                catch (System.IO.FileNotFoundException e)
                {
                    log.Add(e.Message);
                    continue;
                }

                // Perform the required action on each file here.
                // Modify this block to perform your required task.
                foreach (string file in files)
                {
                    try
                    {
                        if (DesiredFileType(file))
                        {
                            GetPEInfo(file);
                        }
                    }
                    catch (System.IO.FileNotFoundException e)
                    {
                        // If file was deleted by a separate application
                        // or thread since the call to TraverseTree()
                        // then just continue.
                        log.Add(e.Message);
                        continue;
                    }
                }

                // Push the subdirectories onto the stack for traversal.
                // This could also be done before handling the files.
                foreach (string str in subDirs)
                {
                    dirs.Push(str);
                }
            }

            Console.WriteLine(@"{0}: the total number of executables", total);

            foreach (string s in log)
            {
                Console.WriteLine("\n\n");

                Console.WriteLine(s);
            }
        }



        static void GetPEInfo(string fileName)
        {
            const string s1 = "  --  32 bit Managed Code";
            const string s2 = "  --  64 bit Managed Code";
            const string s3 = "  --  32 bit Native Code";
            const string s4 = "  --  64 bit Native Code";

            uint peHeader;

            try
            {
                Stream peFileStream = new FileStream(fileName, FileMode.Open, FileAccess.Read);
                BinaryReader peReader = new BinaryReader(peFileStream, System.Text.Encoding.ASCII);

                // 1. Check DOS signature
                char M, Z;

                M = peReader.ReadChar();
                Z = peReader.ReadChar();

                if ((M != 'M') || (Z != 'Z'))
                {
                    return;  // Error out
                }


                // 2. Check PE signature
                //
                // PE Header starts at 0x3C
                peFileStream.Position = 0x3C;

                // Find the PE signature position
                peHeader = peReader.ReadUInt32();

                // Move to PE signature start location
                peFileStream.Position = peHeader;

                // Valid PE signature has 4 bytes: "PE\0\0"
                char P, E, z1, z2;

                P = peReader.ReadChar();
                E = peReader.ReadChar();
                z1 = peReader.ReadChar();
                z2 = peReader.ReadChar();

                if ((P != 'P') || (E != 'E') || (z1 != 0) || (z2 != 0))
                {
                    return;  // Error out
                }


                // 3. Read COFF header (for both COFF object files and PE files)
                //
                ushort Machine;                                    // shows what machine the image file is compiled for
                ushort NumberOfSections;
                uint TimeDateStamp;
                uint PointerToSymbolTable;
                uint NumberOfSymbols;
                ushort SizeOfOptionalHeader;
                ushort Characteristics;

                Machine = peReader.ReadUInt16();                  // we'll use this later to show 32 or 64 bit code of the PE image
                NumberOfSections = peReader.ReadUInt16();
                TimeDateStamp = peReader.ReadUInt32();
                PointerToSymbolTable = peReader.ReadUInt32();
                NumberOfSymbols = peReader.ReadUInt32();
                SizeOfOptionalHeader = peReader.ReadUInt16();
                Characteristics = peReader.ReadUInt16();


                // 4. Process PE Optional Header
                // the offset varies depending on the PE Magic field being PE (0x10B) or PE+ (0x20B)
                ushort Magic = peReader.ReadUInt16();

                ushort offset;

                if (Magic == 0x10B)
                {
                    offset = 96;
                }
                else if (Magic == 0x20B)
                {
                    offset = 112;
                }
                else  // invalid value
                {
                    return;  // error out
                }

                // We directly to data_directory DataDirectory[16] by skipping 30 fields (96 bytes in total)
                ushort dataDictionaryStart;

                dataDictionaryStart = Convert.ToUInt16(Convert.ToUInt16(peFileStream.Position) + offset - 2); // as we have read 2 bytes header, which is taken consideration here.
                peFileStream.Position = dataDictionaryStart;


                // 5. Read 16 data directories  (two 4-byte fields)
                uint[] VirtualAddress = new uint[16];
                uint[] Size = new uint[16];

                for (int i = 0; i < 15; i++)
                {
                    VirtualAddress[i] = peReader.ReadUInt32();
                    Size[i] = peReader.ReadUInt32();
                }

                // 6. CLR is located at the 15th directory
                // "5.10.The .cormeta Section (Object Only)
                // CLR metadata is stored in this section. It is used to indicate that the object file 
                // contains managed code. The format of the metadata is not documented, but can be 
                // handed to the CLR interfaces for handling metadata." <<Microsoft PE and COFF Specification, Rev. 8.3>>
				// https://docs.microsoft.com/en-us/windows/win32/debug/pe-format

                uint clrRuntimeHeader = VirtualAddress[14];

                string winPlatform = (Machine == 0x8664) ? "64 bit" : (Machine == 0x14c) ? "32 bit" : "";

                if (clrRuntimeHeader > 0)  // CLR header found
                {
                    Console.Write(fileName);
                    if (Machine == 0x14c)
                    {
                        total++;

                        Console.WriteLine(s1);
                    } 
                    else if (Machine == 0x8664)
                    {
                        total++;

                        Console.WriteLine(s2);
                    }
                    else
                    {
                        Console.WriteLine ("unknown");
                    }
                }
                else
                {
                    Console.Write(fileName);
                    if (Machine == 0x14c)
                    {
                        total++;

                        Console.WriteLine(s3);
                    } 
                    else if (Machine == 0x8664)
                    {
                        total++;

                        Console.WriteLine(s4);
                    }
                    else
                    {
                        Console.WriteLine ("unknown");
                    }
                }

                peFileStream.Close();
            }
            catch (Exception e)  // something is terribly wrong, for instance, 16 bit exe which we cannot handle it.
            {
                log.Add(e.Message);
                return;
            }

        }

    }
}
