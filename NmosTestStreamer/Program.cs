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

namespace NmosTestStreamer
{
    class Program
    {
        private static UdpClient _outputClient;
        private static string _outputAdapterAddress;
        private static byte[][] _bytePayloads;
        private static int _packetCount;
        private static int _totalGrains;
        private static int _msPerGrain = -1;

        private static void Main(string[] args)
        {
            try
            {
                // Check command line
                if (args.Length < 2 || args.Length > 3)
                {
                    Console.WriteLine("usage: " + Environment.GetCommandLineArgs()[0] + " filename outputadapteraddress [mspergrain]");
                    Console.WriteLine("<hit enter to exit>");
                    Console.ReadLine();
                    return;
                }

                _outputAdapterAddress = args[1];
                if (args.Length == 3)
                {
                    _msPerGrain = Convert.ToInt32(args[2]);
                }

                while (_packetCount == 0)
                {
                    // Create the offline device
                    var selectedDevice = new OfflinePacketDevice(args[0]);

                    // Create output UDP streaming client
                    _outputClient = PrepareOutputClient("232.0.7.1", 5000);

                    Console.WriteLine($"Sending contained packets from {args[0]} to adapter {args[1]}");
                    
                    // Open the capture file
                    using (var communicator =
                        selectedDevice.Open(65536,                                  // portion of the packet to capture
                                                                                    // 65536 guarantees that the whole packet will be captured on all the link layers
                                            PacketDeviceOpenAttributes.Promiscuous, // promiscuous mode
                                            1000))                                  // read timeout
                    {
                        // Read and dispatch packets until EOF is reached
                        communicator.ReceivePackets(0, DispatcherHandler);
                        
                    }

                    //since we don't know the PCAP length, just read once and pre-allocate buffer; then re-read and populate buffer
                    //lazy, inefficient - but reliable and no impact once startup complete
                    if (_bytePayloads != null) continue;

                    _bytePayloads = new byte[_packetCount][];
                    _packetCount = 0;
                }
               
                ushort seqNum = 0;

                var firstpacket = new RtpPacket(_bytePayloads[0]);
                var lastpacket = new RtpPacket(_bytePayloads[_packetCount - 1]);
                var timestampSpan = (int)((lastpacket.Timestamp - firstpacket.Timestamp) / 90);

                int timeBetweenGrains;
                _totalGrains = _totalGrains / 2;

                if (_totalGrains > 1) { 
                     timeBetweenGrains = timestampSpan / (_totalGrains - 1);
                }
                else
                {
                    timeBetweenGrains = timestampSpan;
                }

                if (timeBetweenGrains == 0 && timeBetweenGrains < 0)
                {
                    timeBetweenGrains = 40;
                }
                else
                {
                    timeBetweenGrains = _msPerGrain;
                }
                
                var outputStartTime = DateTime.UtcNow.TimeOfDay.TotalMilliseconds;
                
                var loopCount = 0;
                var grainCount = 0;

                while (true)
                {
                    uint currentTimestamp = 0;
                    //repeating payload loop
                    for (var i = 0; i < _packetCount; i++)
                    {
                        var packet = new RtpPacket(_bytePayloads[i]);
                        if (currentTimestamp != packet.Timestamp)
                        {
                            //RTP packet timestamp has changed - will be a new frame set
                            
                            //how much time should have passed since playback began?
                            var totalExpectedElapsed = grainCount * timeBetweenGrains + (loopCount * _totalGrains * timeBetweenGrains);
                            var diffTotal = (totalExpectedElapsed + outputStartTime) - DateTime.UtcNow.TimeOfDay.TotalMilliseconds;
                            
                            if (diffTotal > 0)
                            {
                                System.Threading.Thread.Sleep((int)diffTotal);
                            }
                            
                            currentTimestamp = packet.Timestamp;
                            grainCount++;
                        }

                        packet.SequenceNumber = seqNum++;
                        packet.Timestamp = (uint)(loopCount * (timeBetweenGrains * _totalGrains * 90) + (grainCount * timeBetweenGrains * 90));
                        var newBuf = packet.GetPacket();
                        _outputClient.Send(newBuf, packet.PacketSize);
                        
                    }

                    loopCount++;
                    
                }
            }
            catch (Exception ex)
            {
                PrintToConsole("Exception trying to play back PCAP: " + ex.Message);
                Console.WriteLine("<hit enter to exit>");
                Console.ReadLine();
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

            var ip = packet.Ethernet.IpV4;
            var udp = ip.Udp;
            var rtpPayload = new byte[udp.Payload.Length];

            var payloadLen = rtpPayload.Length;
            var srcOffset = packet.Ethernet.Length - payloadLen;
          
            Buffer.BlockCopy(packet.Buffer, srcOffset, rtpPayload, 0, payloadLen);

            var rtpPacket = new RtpPacket(rtpPayload);

            if (rtpPacket.Extension)
            {
                //count grains by the existence of RTP headers taking a reasonable size
                //should count using NMOS GrainFlag start - but since the structure is in flux, it is best to use this more brutal method
                if ((rtpPacket.HeaderSize - 12) > 50)
                {
                    _totalGrains++;
                }
            }
            
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
            client.Client.SendBufferSize = 1024 * 256 * 8;  //quite large buffer, since at uncompressed rates it can get full (and this is jsut a debug tool anyway)
            client.ExclusiveAddressUse = false;
            client.Client.Bind(localEp);

            var parsedMcastAddr = IPAddress.Parse(multicastAddress);
            client.Connect(parsedMcastAddr, multicastGroup);

            return client;
        }
        
        private static void PrintToConsole(string message)
        {
            Console.WriteLine(message);
        }


    }
}
