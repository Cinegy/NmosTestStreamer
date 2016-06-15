/*
   Copyright 2016 Cinegy GmbH

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.

*/

using System;
using PcapDotNet.Core;
using PcapDotNet.Packets;
using System.Net.Sockets;
using System.Net;
using PcapDotNet.Packets.IpV4;
using PcapDotNet.Packets.Transport;
using System.Collections.Generic;

namespace NmosTestStreamer
{
    class Program
    {
        private static UdpClient _outputClient;
        private static string _outputAdapterAddress;
        private static byte[][] _bytePayloads;
        private static int _packetCount;
        private static List<byte[]> _dataPayloads = new List<byte[]>();
        private static bool startWriting = false;
        private static byte[] frameData = null;

        static void Main(string[] args)
        {
            try
            {
                // Check command line
                if (args.Length != 2)
                {
                    Console.WriteLine("usage: " + Environment.GetCommandLineArgs()[0] + " <filename> <outputadapteraddress>");
                    Console.ReadLine();
                    return;
                }

                _outputAdapterAddress = args[1];

                while (_packetCount == 0)
                {
                    // Create the offline device
                    OfflinePacketDevice selectedDevice = new OfflinePacketDevice(args[0]);

                    // Create output UDP streaming client
                    _outputClient = PrepareOutputClient("239.1.1.2", 1234);

                    Console.WriteLine($"Sending contained packets from {args[0]} to adapter {args[1]}");

                    // Open the capture file
                    using (PacketCommunicator communicator =
                        selectedDevice.Open(65536,                                  // portion of the packet to capture
                                                                                    // 65536 guarantees that the whole packet will be captured on all the link layers
                                            PacketDeviceOpenAttributes.Promiscuous, // promiscuous mode
                                            1000))                                  // read timeout
                    {
                        // Read and dispatch packets until EOF is reached
                        communicator.ReceivePackets(0, DispatcherHandler);
                        //communicator.Dispose();
                    }

                    //since we don't know the PCAP length, just read once and pre-allocate buffer; then re-read and populate buffer
                    //lazy, inefficient - but reliable and no impact once startup complete
                    if (_bytePayloads == null)
                    {
                        _bytePayloads = new byte[_packetCount][];
                        _packetCount = 0;
                    }

                    selectedDevice = null;
                }

                ushort seqNum = 0;

                while (true)
                {
                    //repeating payload loop
                    for (var i = 0; i < _packetCount; i++)
                    {
                        RtpPacket packet = new RtpPacket(_bytePayloads[i]);
                        packet.SequenceNumber = seqNum++;
                        var newBuf = packet.GetPacket();
                        _outputClient.Send(newBuf, packet.PacketSize);

                        //todo: implement a proper timing model here - very approx AVC rate simulated here
                        if (i % 16 == 0)
                        {
                           System.Threading.Thread.Sleep(1);
                        }
                    }
                    Console.WriteLine($"Loop: {DateTime.Now.TimeOfDay}");
                }
            }
            catch (Exception ex)
            {
                PrintToConsole("Exception trying to play back PCAP: " + ex.Message);
            }
        }

        private static void DispatcherHandler(Packet packet)
        {
            //just count packets if payload storage is null
            if (_bytePayloads == null)
            {
                _packetCount++;
                return;
            }

            IpV4Datagram ip = packet.Ethernet.IpV4;
            UdpDatagram udp = ip.Udp;
            var rtpPayload = new byte[udp.Payload.Length];

            Buffer.BlockCopy(packet.Buffer, packet.Ethernet.Arp.HeaderLength + ip.HeaderLength + packet.Ethernet.HeaderLength, rtpPayload, 0, rtpPayload.Length);

            _bytePayloads[_packetCount++] = rtpPayload;
        }

        private static UdpClient PrepareOutputClient(string multicastAddress, int multicastGroup)
        {
            var outputIp = _outputAdapterAddress != null ? IPAddress.Parse(_outputAdapterAddress) : IPAddress.Any;
            PrintToConsole($"Outputting multicast data to {multicastAddress}:{multicastGroup} via adapter {outputIp}");

            var client = new UdpClient { ExclusiveAddressUse = false };
            var localEp = new IPEndPoint(outputIp, multicastGroup);

            client.Client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
            client.Client.Blocking = false;
            client.Client.SendBufferSize = 1024 * 1024 * 1024;
            client.ExclusiveAddressUse = false;
            client.Client.Bind(localEp);

            var parsedMcastAddr = IPAddress.Parse(multicastAddress);
            client.Connect(parsedMcastAddr, multicastGroup);

            return client;
        }
        
        private static void PrintToConsole(string message, bool verbose = false)
        {
            //if (_logFileStreamWriter != null && _logFileStreamWriter.BaseStream.CanWrite)
            //{
            //    _logFileStreamWriter.WriteLine("{0}\r\n------\r\n{1}", DateTime.Now.ToString("HH:mm:ss"), message);
            //    _logFileStreamWriter.Flush();
            //}

            //if (_options.Quiet)
            //    return;

            //if ((!_options.Verbose) && verbose)
            //    return;

            Console.WriteLine(message);
        }


    }
}
