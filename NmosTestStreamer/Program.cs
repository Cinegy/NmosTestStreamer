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

       // private static StreamWriter _logFileStreamWriter;

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
                    _outputClient = PrepareOutputClient("239.1.1.1", 1234);

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

                ushort seqNum = 100;

                while (true)
                {
                    //repeating payload loop
                    for (var i = 0; i < _packetCount; i++)
                    {
                        RtpPacket packet = new RtpPacket(_bytePayloads[i]);
                        packet.SequenceNumber = seqNum++;
                        var newBuf = packet.GetPacket();
                        ReadH264FromPacket(packet);
                        _outputClient.Send(newBuf, packet.PacketSize);
                        if (i % 2 == 0)
                        {
                            System.Threading.Thread.Sleep(1);
                        }
                    }

                    Console.WriteLine($"Loop: {DateTime.Now.TimeOfDay}");
                }

                Console.WriteLine("Finished - hit enter to quit");

                Console.ReadLine();
            }
            catch
            {

            }
    }

        private static void DispatcherHandler(Packet packet)
        {
            //just count packets if payload storage is null
            if(_bytePayloads==null)
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

        private static void ReadH264FromPacket(RtpPacket bufferedPacket)
        {


            try
            {
                if (bufferedPacket.PayloadType != 97) return;
                
                    if (bufferedPacket.Payload[1] == 0x85) //this byte indicates start of I frame
                    {
                        startWriting = true;
                    }

                    if (bufferedPacket.Padding)
                    {
                        PrintToConsole("RTP Packet has padding... this needs to be removed - not yet implemented!!");
                    }

                    if (startWriting && _bytePayloads != null)
                    {
                        if ((bufferedPacket.Payload[0] & 0x1C) == 0x1c)
                        {
                            switch (bufferedPacket.Payload[1])
                            {
                                case 0x85: //start of new I frame
                                    PrintToConsole(
                                        $"I-frame start - SeqNum: {bufferedPacket.SequenceNumber}, LastTS: {bufferedPacket.Timestamp}",
                                        true);

                                    //sps
                                //    frameData = AddToArray(frameData, new byte[] { 0x0, 0x0, 0x0, 0x01 });
                                //    frameData = AddToArray(frameData, _spsData);
                                    //pps
                                //    frameData = AddToArray(frameData, new byte[] { 0x0, 0x0, 0x0, 0x01 });
                                //    frameData = AddToArray(frameData, _ppsData);
                                    //New IDR NAL
                                    frameData = AddToArray(frameData, new byte[] { 0x0, 0x0, 0x0, 0x01 });
                                    frameData = AddToArray(frameData, 0x45);
                                    frameData = AddToArray(frameData, bufferedPacket.Payload, 2);

                                    break;
                                case 0x81: //start of P / B frame
                                    frameData = AddToArray(frameData, new byte[] { 0x0, 0x0, 0x0, 0x01 });
                                    frameData = AddToArray(frameData, 0x41);
                                    frameData = AddToArray(frameData, bufferedPacket.Payload, 2);

                                    break;
                                case 0x05: //body of I frame
                                    frameData = AddToArray(frameData, bufferedPacket.Payload, 2);
                                    break;
                                case 0x01: //body of P / B frame
                                    frameData = AddToArray(frameData, bufferedPacket.Payload, 2);
                                    break;
                                case 0x41: //end of P / B frame

                                    frameData = AddToArray(frameData, bufferedPacket.Payload, 2);

                                    //unsafe
                                    //{
                                    //    fixed (byte* p = frameData)
                                    //    {
                                    //        _tsWriter.ProcessData((IntPtr)p, (uint)frameData.Length);
                                    //    }
                                    //}

                                   // _elemFileBinaryWriter?.Write(frameData);

                                    frameData = null;

                                    break;
                                case 0x45: //end of I frame

                                    frameData = AddToArray(frameData, bufferedPacket.Payload, 2);

                                    //unsafe
                                    //{
                                    //    fixed (byte* p = frameData)
                                    //    {
                                    //        _tsWriter.ProcessData((IntPtr)p, (uint)frameData.Length);
                                    //    }
                                    //}

                                    //_elemFileBinaryWriter?.Write(frameData);

                                    frameData = null;

                                    break;
                                default:
                                    var printLen = 3;

                                    if (printLen > bufferedPacket.Payload.Length)
                                        printLen = bufferedPacket.Payload.Length;

                                    var payloadString = BitConverter.ToString(bufferedPacket.Payload, 0, printLen);

                                    PrintToConsole(
                                        $"Unexpected indicator: 0x{bufferedPacket.Payload[1]:X}, Len: {bufferedPacket.Payload.Length}, First few bytes: {payloadString}",
                                        true);

                                    frameData = AddToArray(frameData, bufferedPacket.Payload, 2);

                                    break;
                            }
                        }
                        else //not an FU-A packed payload
                        {
                            if ((bufferedPacket.Payload[0] & 0x09) == 0x09)
                            {
                                if (bufferedPacket.Payload.Length < 1300)
                                {
                                    //access unit delimiter in plain NALU payload
                                    frameData = AddToArray(frameData, new byte[] { 0x0, 0x0, 0x0, 0x01, 0x09 });
                                    frameData = AddToArray(frameData, bufferedPacket.Payload, 2);
                                }
                            }
                            else if ((bufferedPacket.Payload[0] & 0x07) == 0x07)
                            {
                                //SPS
                            }
                            else if ((bufferedPacket.Payload[0] & 0x08) == 0x08)
                            {
                                //PPS
                            }
                            else if ((bufferedPacket.Payload[0] & 0x06) == 0x06)
                            {
                                //SEI data
                                if (bufferedPacket.Payload.Length < 1380)
                                {
                                    //access unit delimiter in plain NALU payload
                                    frameData = AddToArray(frameData, new byte[] { 0x0, 0x0, 0x0, 0x01 });
                                    frameData = AddToArray(frameData, bufferedPacket.Payload);
                                }
                            }
                            else if ((bufferedPacket.Payload[0] & 0x01) == 0x01)
                            {
                                //B or P frame (small payload case, total NAL in one packet
                                if (bufferedPacket.Payload.Length < 1380)
                                {
                                    //access unit delimiter in plain NALU payload
                                    frameData = null;

                                    frameData = AddToArray(frameData, new byte[] { 0x0, 0x0, 0x0, 0x01 });
                                    frameData = AddToArray(frameData, bufferedPacket.Payload);

                                    //unsafe
                                    //{
                                    //    fixed (byte* p = frameData)
                                    //    {
                                    //        _tsWriter.ProcessData((IntPtr)p, (uint)frameData.Length);
                                    //    }
                                    //}

                                    //_elemFileBinaryWriter?.Write(frameData);

                                    frameData = null;
                                }
                            }
                            else
                            {
                                //unknown / never seen so far
                                var printLen = 3;

                                if (printLen > bufferedPacket.Payload.Length)
                                    printLen = bufferedPacket.Payload.Length;

                                var payloadString = BitConverter.ToString(bufferedPacket.Payload, 0, printLen);

                                PrintToConsole(
                                    $"Non FU-A payload, Length: {bufferedPacket.Payload.Length}, First few bytes: {payloadString}",
                                    true);
                            }
                        }
                    }
                }
            catch (Exception ex)
            {
                PrintToConsole($@"Unhandled exception within network receiver: {ex.Message}");
            }
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


        private static byte[] AddToArray(byte[] arr, byte[] add, int from_byte = 0)
        {
            var arr_size = 0;
            var add_size = add.Length - from_byte;
            byte[] result;

            if (arr == null)
            {
                result = new byte[add_size];
            }
            else
            {
                arr_size = arr.Length;
                result = new byte[arr_size + add_size];
                arr.CopyTo(result, 0);
            }

            Array.Copy(add, from_byte, result, arr_size, add_size);

            return result;
        }
        private static byte[] AddToArray(byte[] arr, byte val)
        {
            var result = new byte[arr.Length + 1];
            arr.CopyTo(result, 0);
            result[arr.Length] = val;

            return result;
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
