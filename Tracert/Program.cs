using System;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;

class Program
{
    private const int ICMP_ECHO = 8; // ICMP Echo Request type
    private const int BUFFER_SIZE = 32; // Payload size
    private const int DEFAULT_TIMEOUT = 3000; // 3 seconds timeout per hop

    static void Main(string[] args)
    {

        Console.WriteLine("Введите домен или IP-адрес:");
        string? destination = Console.ReadLine();
        if (string.IsNullOrEmpty(destination))
        {
            Console.WriteLine("Неверные данные");
            return;
        }

        Regex regex = new Regex("[0-1]?[0-9]?[0-9]|[2][0-4][0-9]|25[0-5].[0-1]?[0-9]?[0-9]|[2][0-4][0-9]|25[0-5].[0-1]?[0-9]?[0-9]|[2][0-4][0-9]|25[0-5].[0-1]?[0-9]?[0-9]|[2][0-4][0-9]|25[0-5]");
        try
        {
            IPHostEntry host = Dns.GetHostEntry(destination);
            string ip = "";
            if (regex.IsMatch(destination))
            {
                ip = destination;
                destination = host.HostName;
            }
            IPAddress ipAddress = Dns.GetHostEntry(destination).AddressList[0];
            if (ip == "")
                ip = ipAddress.ToString();
            Console.WriteLine($"Tracing route to {destination} [{ip}]...\n");

            TraceRoute(ipAddress);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error: {ex.Message}");            
        }
        Console.ReadKey();
    }

    static void TraceRoute(IPAddress destination)
    {
        using (Socket socket = new Socket(AddressFamily.InterNetwork, SocketType.Raw, ProtocolType.Icmp))
        {
            socket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReceiveTimeout, DEFAULT_TIMEOUT);
            IPEndPoint destinationEndPoint = new IPEndPoint(destination, 0);
            byte[] buffer = new byte[BUFFER_SIZE];
            Random rnd = new Random();
            rnd.NextBytes(buffer); 

            for (int ttl = 1; ttl <= 30; ttl++) 
            {
                socket.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.IpTimeToLive, ttl);

                Console.Write($"ttl={ttl}:");

                // Create ICMP Echo Request packet
                byte[] packet = CreateIcmpPacket(buffer);
                
                for (int i = 0; i < 3; i++)
                {
                    socket.SendTo(packet, destinationEndPoint);

                    DateTime startTime = DateTime.Now;
                    EndPoint remoteEndPoint = new IPEndPoint(IPAddress.Any, 0);
                    byte[] receiveBuffer = new byte[256];

                    try
                    {
                        int bytesReceived = socket.ReceiveFrom(receiveBuffer, ref remoteEndPoint);
                        TimeSpan time = DateTime.Now - startTime;
                        IPAddress hopAddress = ((IPEndPoint)remoteEndPoint).Address;

                        Console.Write($"\t{time.TotalMilliseconds,4:F0} ms");
                        if (i == 2)
                        {
                            try
                            {
                                IPHostEntry entry = Dns.GetHostEntry(hopAddress);
                                if (entry.HostName != null)
                                    Console.Write($"  {entry.HostName}");
                            }
                            catch (Exception) { }
                            
                            Console.WriteLine($"  [{hopAddress}]");
                            
                            if (destination.Equals(((IPEndPoint)remoteEndPoint).Address))
                            {
                                Console.WriteLine("\nТрассировка завершена");
                                return;
                            }                              
                        }                        
                    }
                    catch (SocketException)
                    {
                        Console.Write($"\t * ");
                        if (i == 2)
                        {
                            Console.WriteLine($"\t Request timed out.");
                        }
                    }
                }
                Thread.Sleep(500); 
            }
        }
    }

    static byte[] CreateIcmpPacket(byte[] data)
    {
        byte[] packet = new byte[8 + data.Length]; // ICMP header + data
        packet[0] = ICMP_ECHO; // Type
        packet[1] = 0;         // Code
        packet[2] = 0;         // Checksum placeholder
        packet[3] = 0;
        packet[4] = 0;         // Identifier
        packet[5] = 1;
        packet[6] = 0;         // Sequence number
        packet[7] = 1;

        Array.Copy(data, 0, packet, 8, data.Length);

        // Calculate checksum
        int checksum = CalculateChecksum(packet);
        packet[2] = (byte)(checksum >> 8);
        packet[3] = (byte)(checksum & 0xFF);

        return packet;
    }

    static int CalculateChecksum(byte[] packet)
    {
        int checksum = 0;
        for (int i = 0; i < packet.Length; i += 2)
        {
            checksum += (packet[i] << 8) + (i + 1 < packet.Length ? packet[i + 1] : 0);
        }
        checksum = (checksum >> 16) + (checksum & 0xFFFF);
        checksum += (checksum >> 16);
        return ~checksum & 0xFFFF;
    }
}