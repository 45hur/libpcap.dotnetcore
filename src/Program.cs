using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace LibPcap
{
    class Program
    {
        private static readonly log4net.ILog log = log4net.LogManager.GetLogger(MethodBase.GetCurrentMethod().DeclaringType);

        private static void LoadLogConfig()
        {
            var repo = log4net.LogManager.CreateRepository(Assembly.GetEntryAssembly(), typeof(log4net.Repository.Hierarchy.Hierarchy));
            log4net.GlobalContext.Properties["pid"] = Process.GetCurrentProcess().Id;

            log4net.Config.XmlConfigurator.ConfigureAndWatch(repo, new FileInfo("log4net.config"));
        }

        [DllImport("libpcap", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Auto)]
        internal extern static int pcap_findalldevs(ref IntPtr alldevs, StringBuilder errbuf);

        [DllImport("libpcap", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Auto)]
        internal extern static void pcap_freealldevs(IntPtr alldevs);

        [DllImport("libpcap", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        internal extern static IntPtr pcap_open_live(string device, int snaplen, int promisc, int to_ms, StringBuilder errbuf);

        [DllImport("libpcap", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        internal extern static int pcap_sendpacket(IntPtr p, byte[] packet, int size);

        [DllImport("libpcap", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Auto)]
        internal extern static IntPtr pcap_loop(IntPtr p, int cnt, [MarshalAs(UnmanagedType.FunctionPtr)]LoopCallback callback, IntPtr user);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        internal delegate void LoopCallback(IntPtr args, IntPtr header, IntPtr data);

        [StructLayout(LayoutKind.Sequential)]
        internal struct PcapIf
        {
            public IntPtr Next;
            public string Name;
            public string Description;
            public IntPtr Addresses;
            public uint Flags;
        };

        [StructLayout(LayoutKind.Sequential)]
        internal struct PcapAddr
        {
            public IntPtr Next;
            public IntPtr Address;
            public IntPtr Netmask;
            public IntPtr Broadcast;
            public IntPtr Destination;
        };

        [StructLayout(LayoutKind.Sequential)]
        internal struct SockAddr
        {
            public ushort sa_family;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 14)]
            public byte[] sa_data;
        }

        [StructLayout(LayoutKind.Sequential)]
        unsafe internal struct SockAddr_In
        {
            public short sin_family;
            public ushort sin_port;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
            public byte[] sin_addr;
            public fixed byte sin_zero[8];
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct SockAddr_In6
        {
            public ushort sin6_family;
            public ushort sin6_port;
            public uint sin6_flowinfo;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
            public byte[] sin6_addr;
            public uint sin6_scope_id;
        };

        [StructLayout(LayoutKind.Sequential)]
        internal struct pcap_pkthdr
        {
            public timeval ts;
            public uint caplen;
            public uint len;
        };

        [StructLayout(LayoutKind.Sequential)]
        internal struct timeval
        {
            public IntPtr tv_sec;
            public IntPtr tv_usec;
        };



        internal static void PrintAllDevices()
        {
            log.Debug("PrintAllDevices");

            var errbuf = new StringBuilder(256 /*PCAP_ERRBUF_SIZE*/);
            var d = IntPtr.Zero;
            var alldevs = IntPtr.Zero;

            if (-1 == pcap_findalldevs(ref alldevs, errbuf))
            {
                log.Error($"pcap_findalldevs failed, er: {errbuf.ToString()}");
                return;
            }

            int j = 0;

            log.Info($"Interfaces: ");
            d = alldevs;

            while (d != IntPtr.Zero)
            {
                var ifc = (PcapIf)Marshal.PtrToStructure(d, typeof(PcapIf));
                log.Info($"{ifc.Name}");

                log.Info($" Addresses: ");
                var a = ifc.Addresses;
                while (a != IntPtr.Zero)
                {
                    var addr = (PcapAddr)Marshal.PtrToStructure(a, typeof(PcapAddr));
                    if (addr.Address != IntPtr.Zero)
                    {
                        var sockaddr = (SockAddr)Marshal.PtrToStructure(addr.Address, typeof(SockAddr));
                        log.Info($" Family: {sockaddr.sa_family}");

                        if (sockaddr.sa_family == 2)
                        {
                            var ipaddrv4 = (SockAddr_In)Marshal.PtrToStructure(addr.Address, typeof(SockAddr_In));
                            var ipaddr = new IPAddress(ipaddrv4.sin_addr);
                            log.Info($"  Address: {ipaddr.ToString()}");
                        }

                        if (sockaddr.sa_family == 17)
                        {
                            var ipaddrv6 = (SockAddr_In6)Marshal.PtrToStructure(addr.Address, typeof(SockAddr_In6));
                            var ipaddr = new IPAddress(ipaddrv6.sin6_addr);
                            log.Info($"  Address: {ipaddr.ToString()}");
                        }
                    }

                    a = addr.Next;
                }

                d = ifc.Next;
            }

            pcap_freealldevs(alldevs);
        }

        internal static bool DeviceOpen(string deviceName)
        {
            log.Debug($"DeviceOpen {deviceName}");

            var errbuf = new StringBuilder(256 /*PCAP_ERRBUF_SIZE*/);
            IntPtr adhandle = IntPtr.Zero;

            if ((adhandle = pcap_open_live(
                deviceName,
                65536,            //portion of the packet to capture. 
                1,                //PCAP_OPENFLAG_PROMISCUOUS
                1000,             // read timeout
                errbuf
            )) == IntPtr.Zero)
            {
                log.Error($"pcap_open_live failed, er: {errbuf.ToString()}");
                return false;
            }

            //Thread argument
            object arg = adhandle;
            var task = new TaskFactory().StartNew(new Action<object>((buff) =>
            {
                while (true)
                {
                    var packet = CreateIPv4Packet("02:42:AC:11:00:01", "02:42:AC:11:00:02", IPAddress.Parse("172.17.0.1"), IPAddress.Parse("172.17.0.2"), 1337, 1337, new byte[] { 1, 2, 3, 4 });

                    log.Info($"Sending packet {packet.Length}");
                    if (-1 == pcap_sendpacket(adhandle, packet, packet.Length))
                    {
                        log.Error($"pcap_sendpacket failed");
                    }

                    Thread.Sleep(5000);
                }
            }), arg);
            //End thread

            pcap_loop(adhandle, 0, (args, header, bytes) =>
            {
                var hdr = (pcap_pkthdr)Marshal.PtrToStructure(header, typeof(pcap_pkthdr));
                log.Debug($"caplen={hdr.caplen};len={hdr.len}");

                var pkt_data = new byte[hdr.caplen];
                Marshal.Copy(bytes, pkt_data, 0, (int)hdr.caplen);

            }, IntPtr.Zero);

            return true;

        }

        internal static byte[] CreateIPv4Packet(string src, string dst,
            IPAddress ipsrc, IPAddress ipdst,
            ushort srcp, ushort dstp,
            byte[] data)
        {
            var result = new byte[data.Length + 42];

            byte[] arrSrc = src.Split(':').Select(x => Convert.ToByte(x, 16)).ToArray();
            byte[] arrDst = dst.Split(':').Select(x => Convert.ToByte(x, 16)).ToArray();
            byte[] arrIpSrc = ipsrc.GetAddressBytes();
            byte[] arrIpDst = ipdst.GetAddressBytes();
            byte[] arrSrcp = BitConverter.GetBytes(srcp).Reverse().ToArray();
            byte[] arrDstp = BitConverter.GetBytes(dstp).Reverse().ToArray();

            Array.Copy(arrDst, 0, result, 0, 6);
            Array.Copy(arrSrc, 0, result, 6, 6);
            Array.Copy(new byte[] { 0x08, 0x00, 0x45, 0x00 }, 0, result, 12, 4);
            var len = data.Length + 28;
            var arrLen = BitConverter.GetBytes((ushort)len).Reverse().ToArray();
            Array.Copy(arrLen, 0, result, 16, 2);

            Array.Copy(new byte[] { 0x13, 0x37, 0x00, 0x00, 0x80, 0x11, 0x00, 0x00 }, 0, result, 18, 8);

            Array.Copy(arrIpSrc, 0, result, 26, 4);
            Array.Copy(arrIpDst, 0, result, 30, 4);
            Array.Copy(arrSrcp, 0, result, 34, 2);
            Array.Copy(arrDstp, 0, result, 36, 2);

            var udpLen = data.Length + 8;
            var arrUdpLen = BitConverter.GetBytes((ushort)udpLen).Reverse().ToArray();
            Array.Copy(arrUdpLen, 0, result, 38, 2);

            Array.Copy(data, 0, result, 42, data.Length);

            var udpChecksum = CalculateUDPChecksum(result);
            var arrUdpChecksum = BitConverter.GetBytes((ushort)udpChecksum).Reverse().ToArray();
            Array.Copy(arrUdpChecksum, 0, result, 40, 2);

            var ipChecksum = CalculateIPChecksum(result);
            var arrIpChecksum = BitConverter.GetBytes((ushort)ipChecksum).Reverse().ToArray();
            Array.Copy(arrIpChecksum, 0, result, 24, 2);

            return result;
        }

        internal static ushort CalculateUDPChecksum(byte[] data)
        {
            uint csum = 0;
            var PseudoLength = data.Length + 17;           
            PseudoLength += PseudoLength % 2;              
            var Length = data.Length + 8;                  
            var PseudoHeader = new byte[PseudoLength];

            PseudoHeader[0] = 0x11;                        
            Array.Copy(data, 26, PseudoHeader, 1, 8);

            var arrLength = BitConverter.GetBytes((ushort)Length).Reverse().ToArray();
            Array.Copy(arrLength, 0, PseudoHeader, 9, 2);
            Array.Copy(arrLength, 0, PseudoHeader, 11, 2);

            Array.Copy(data, 34, PseudoHeader, 13, 2);
            Array.Copy(data, 36, PseudoHeader, 15, 2);
            Array.Copy(data, 0, PseudoHeader, 17, data.Length);

            for (int i = 0; i < PseudoLength; i += 2)
            {
                var word = BitConverter.ToUInt16(PseudoHeader, i);
                var diff = (ushort)(65535 - csum);
                csum += word;
                if (word > diff)
                    csum += 1;
                if (csum > 65535)
                    csum -= 65535;
            }

            csum = ~csum;
            return (ushort)csum;
        }

        internal static ushort CalculateIPChecksum(byte[] packet)
        {
            uint csum = 0;
            for (int i = 14; i < 34; i += 2)
            {
                var word = BitConverter.ToUInt16(packet, i);
                var diff = (ushort)(65535 - csum);
                csum += word;
                if (word > diff)
                    csum += 1;
                if (csum > 65535)
                    csum -= 65535;
            }

            csum = ~csum;
            return (ushort)csum;
        }

        static void Main(string[] args)
        {
            LoadLogConfig();

            log.Debug("Main");

            PrintAllDevices();
            DeviceOpen("eth0");
        }
    }
}
