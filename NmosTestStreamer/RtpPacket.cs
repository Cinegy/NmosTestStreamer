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

namespace NmosTestStreamer
{
    /// <summary>
    /// Represents an RTP packet
    /// </summary>
    public class RtpPacket
    {
        public short Version;
        public bool Padding;
        public bool Extension;
        public int ExtensionLength;
        public short CsrcCount;
        public bool Marker;
        public byte PayloadType;
        public ushort SequenceNumber;
        public uint Timestamp;
        public uint Ssrc;
        public byte[] Payload;
        public byte[] ExtensionHeaderPayload;
        public ushort ExtensionSize;

        public int HeaderSize { get; private set; }

        public int PacketSize
        {
            get
            {
                if(Payload==null)
                {
                    return HeaderSize;
                }

                return HeaderSize + Payload.Length;
            }
        }

        public RtpPacket()
        {
            Version = 2;
            HeaderSize = 12;
        }

        public RtpPacket(byte[] data)
        {
            GetRtpacketFromData(ref data);
        }

        public byte[] GetPacket()
        {
            var buffer = new byte[PacketSize];

            BitWriter bw = new BitWriter(buffer);

            bw.Put_Bits((uint)Version, 2);
            bw.Put_Bool(Padding);
            bw.Put_Bool(Extension);
            bw.Put_Bits((uint)CsrcCount, 4);
            bw.Put_Bool(Marker);
            bw.Put_Bits(PayloadType, 7);
            bw.Put_Bits(SequenceNumber, 16);
            bw.Put_Bits(Timestamp, 32);
            bw.Put_Bits(Ssrc, 32);
            bw.BitPos += CsrcCount * 32;

            if (Extension)
            {
                /* Commented once headers were scaped into payload
                bw.Put_Bits(0xbede, 16);
                bw.Put_Bits((uint)((HeaderSize - 12 - 4) / 4), 16);
                
                //todo: support bit serialising RTP extensions (at the moment, ignoring - very short term)
                bw.BitPos += (HeaderSize - 12 - 4) * 8;
                */
                if (ExtensionHeaderPayload != null && (PacketSize > (bw.BitPos/8) + ExtensionSize))
                {
                    Buffer.BlockCopy(ExtensionHeaderPayload, 0, buffer, (bw.BitPos/8), ExtensionHeaderPayload.Length);
                    bw.BitPos += (ExtensionSize) * 8;
                }

            }

            if (Payload != null && (PacketSize > (bw.BitPos / 8)))
            {
                Buffer.BlockCopy(Payload, 0, buffer, (bw.BitPos / 8), Payload.Length);
            }

            return buffer;
        }


        private void GetRtpacketFromData(ref byte[] data)
        {
            Version = (short)((data[0] & 0xC0) >> 6);
            Padding = ((data[0] & 0x20) >> 5) != 0;
            Extension = ((data[0] & 0x10) >> 4) != 0;
            CsrcCount = (short)(data[0] & 0xF);
            Marker = (data[1] & 0x80) != 0;
            PayloadType = (byte)(data[1] & 0x7F);
            SequenceNumber = (ushort)((data[2] << 8) + data[3]);
            Timestamp = (uint)((data[4] << 24) + (data[5] << 16) + (data[6] << 8) + data[7]);
            Ssrc = (uint)((data[8] << 24) + (data[9] << 16) + (data[10] << 8) + data[11]);

            HeaderSize = 12 + ((32 * CsrcCount)/8);

            if (Extension)
            {
                //read extension header length and payload, and add to current header length
                ExtensionSize = (ushort)(((data[HeaderSize + 2] << 8) + data[HeaderSize + 3] * 4) + 4);
                ExtensionHeaderPayload = new byte[ExtensionSize];
                Buffer.BlockCopy(data, HeaderSize, ExtensionHeaderPayload, 0, ExtensionSize);
                HeaderSize += ExtensionSize;
            }

            Payload = new byte[data.Length - HeaderSize];

            Buffer.BlockCopy(data, HeaderSize, Payload, 0, data.Length - HeaderSize);
        }



    }
}