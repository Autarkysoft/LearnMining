using System;
using System.Collections.Generic;
using System.Runtime.CompilerServices;
using System.Text;

namespace LearnMining.Cryptography
{
    /// <summary>
    /// https://tools.ietf.org/html/rfc6234
    /// </summary>
    public class Sha256 : IHashFunction
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="Sha256"/>.
        /// </summary>
        /// <param name="isDouble">Determines whether the hash should be performed twice.</param>
        public Sha256(bool isDouble = false)
        {
            IsDouble = isDouble;
        }



        /// <summary>
        /// Indicates whether the hash function should be performed twice on message.
        /// For example Double SHA256 that bitcoin uses.
        /// </summary>
        public bool IsDouble { get; set; }

        /// <summary>
        /// Size of the hash result in bytes.
        /// </summary>
        public virtual int HashByteSize => 32;

        /// <summary>
        /// Size of the blocks used in each round.
        /// </summary>
        public virtual int BlockByteSize => 64;


        internal uint[] block = new uint[16];
        internal uint[] hashState = new uint[8];
        protected uint[] w = new uint[64];

        private readonly uint[] Ks =
        {
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
            0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
            0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
            0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
            0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
            0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
            0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
            0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
            0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
        };



        /// <summary>
        /// Computes the hash value for the specified byte array.
        /// </summary>
        /// <exception cref="ArgumentNullException"/>
        /// <exception cref="ObjectDisposedException"/>
        /// <param name="data">The byte array to compute hash for</param>
        /// <returns>The computed hash</returns>
        public byte[] ComputeHash(byte[] data)
        {
            if (disposedValue)
                throw new ObjectDisposedException("Instance was disposed.");
            if (data == null)
                throw new ArgumentNullException(nameof(data), "Data can not be null.");

            Init();

            DoHash(data);

            return GetBytes();
        }



        internal unsafe byte[] GetBytes()
        {
            byte[] res = new byte[HashByteSize];
            fixed (uint* hPt = &hashState[0])
            fixed (byte* bPt = &res[0])
            {
                for (int i = 0, j = 0; i < res.Length; i += 4, j++)
                {
                    bPt[i] = (byte)(hPt[j] >> 24);
                    bPt[i + 1] = (byte)(hPt[j] >> 16);
                    bPt[i + 2] = (byte)(hPt[j] >> 8);
                    bPt[i + 3] = (byte)hPt[j];
                }
            }
            return res;
        }

        internal virtual unsafe void Init()
        {
            fixed (uint* hPt = &hashState[0])
            {
                hPt[0] = 0x6a09e667;
                hPt[1] = 0xbb67ae85;
                hPt[2] = 0x3c6ef372;
                hPt[3] = 0xa54ff53a;
                hPt[4] = 0x510e527f;
                hPt[5] = 0x9b05688c;
                hPt[6] = 0x1f83d9ab;
                hPt[7] = 0x5be0cd19;
            }
        }


        internal unsafe void DoHash(byte[] data)
        {
            fixed (byte* dPt = data) // Data length can be 0 and &data[0] will throw
            fixed (uint* xPt = &block[0], hPt = &hashState[0], wPt = &w[0])
            {
                int remainingBytes = data.Length;
                int dIndex = 0;
                while (remainingBytes >= BlockByteSize)
                {
                    for (int i = 0; i < block.Length; i++, dIndex += 4)
                    {
                        xPt[i] = (uint)((dPt[dIndex] << 24) | (dPt[dIndex + 1] << 16) | (dPt[dIndex + 2] << 8) | dPt[dIndex + 3]);
                    }

                    CompressBlock(xPt, hPt, wPt);

                    remainingBytes -= BlockByteSize;
                }

                byte[] finalBlock = new byte[BlockByteSize];
                fixed (byte* fPt = &finalBlock[0])
                {
                    long msgLen = (long)data.Length << 3; // *8
                    // Message length is added at the end in big-endian order (different from MD4 and RIPEMD160)
                    fPt[63] = (byte)msgLen;
                    fPt[62] = (byte)(msgLen >> 8);
                    fPt[61] = (byte)(msgLen >> 16);
                    fPt[60] = (byte)(msgLen >> 24);
                    fPt[59] = (byte)(msgLen >> 32);
                    /*
                     * Maximum of `msgLen` is (int.MaxValue * 8) = 17179869176
                     * = 00000000_00000000_00000000_00000011_11111111_11111111_11111111_11111000
                     * in other words the first 3 bytes are always zero
                    */
                    //fPt2[58] = (byte)(msgLen >> 40);
                    //fPt2[57] = (byte)(msgLen >> 48);
                    //fPt2[56] = (byte)(msgLen >> 56);

                    if (remainingBytes < 56)
                    {
                        Buffer.BlockCopy(data, data.Length - remainingBytes, finalBlock, 0, remainingBytes);
                        fPt[remainingBytes] = 0b1000_0000;

                        for (int i = 0, j = 0; i < block.Length; i++, j += 4)
                        {
                            xPt[i] = (uint)((fPt[j] << 24) | (fPt[j + 1] << 16) | (fPt[j + 2] << 8) | fPt[j + 3]);
                        }

                        CompressBlock(xPt, hPt, wPt);
                    }
                    else // if (remainingBytes >= 56)
                    {
                        byte[] finalBlock0 = new byte[BlockByteSize];
                        Buffer.BlockCopy(data, data.Length - remainingBytes, finalBlock0, 0, remainingBytes);
                        fixed (byte* fPt0 = &finalBlock0[0])
                        {
                            fPt0[remainingBytes] = 0b1000_0000;

                            for (int i = 0, j = 0; i < block.Length; i++, j += 4)
                            {
                                xPt[i] = (uint)((fPt0[j] << 24) | (fPt0[j + 1] << 16) | (fPt0[j + 2] << 8) | fPt0[j + 3]);
                            }

                            CompressBlock(xPt, hPt, wPt);

                            for (int i = 0, j = 0; i < block.Length; i++, j += 4)
                            {
                                xPt[i] = (uint)((fPt[j] << 24) | (fPt[j + 1] << 16) | (fPt[j + 2] << 8) | fPt[j + 3]);
                            }

                            CompressBlock(xPt, hPt, wPt);
                        }
                    }
                }
            }

            if (IsDouble)
            {
                DoSecondHash();
            }
        }

        internal virtual unsafe void DoSecondHash()
        {
            fixed (uint* xPt = &block[0], hPt = &hashState[0], wPt = &w[0])
            {
                // Result of previous hash (hashState[]) is now our new block. So copy it here:
                xPt[0] = hPt[0];
                xPt[1] = hPt[1];
                xPt[2] = hPt[2];
                xPt[3] = hPt[3];
                xPt[4] = hPt[4];
                xPt[5] = hPt[5];
                xPt[6] = hPt[6];
                xPt[7] = hPt[7]; // 8*4 = 32 byte hash result

                xPt[8] = 0b10000000_00000000_00000000_00000000U; // 1 followed by 0 bits to fill pad1
                xPt[9] = 0;
                xPt[10] = 0;
                xPt[11] = 0;
                xPt[12] = 0;
                xPt[13] = 0;

                xPt[14] = 0; // Message length for pad2, since message is the 32 byte result of previous hash, length is 256 bit
                xPt[15] = 256;

                // Now initialize hashState to compute next round
                Init();

                // We only have 1 block so there is no need for a loop.
                CompressBlock(xPt, hPt, wPt);
            }
        }

        internal unsafe void CompressBlock(uint* xPt, uint* hPt, uint* wPt)
        {
            for (int i = 0; i < 16; i++)
            {
                wPt[i] = xPt[i];
            }
            for (int i = 16; i < w.Length; i++)
            {
                wPt[i] = SSIG1(wPt[i - 2]) + wPt[i - 7] + SSIG0(wPt[i - 15]) + wPt[i - 16];
            }

            uint a = hPt[0];
            uint b = hPt[1];
            uint c = hPt[2];
            uint d = hPt[3];
            uint e = hPt[4];
            uint f = hPt[5];
            uint g = hPt[6];
            uint h = hPt[7];

            uint temp, aa, bb, cc, dd, ee, ff, hh, gg;

            fixed (uint* kPt = &Ks[0])
            {
                for (int j = 0; j < 64;)
                {
                    temp = h + BSIG1(e) + CH(e, f, g) + kPt[j] + wPt[j];
                    ee = d + temp;
                    aa = temp + BSIG0(a) + MAJ(a, b, c);
                    j++;

                    temp = g + BSIG1(ee) + CH(ee, e, f) + kPt[j] + wPt[j];
                    ff = c + temp;
                    bb = temp + BSIG0(aa) + MAJ(aa, a, b);
                    j++;

                    temp = f + BSIG1(ff) + CH(ff, ee, e) + kPt[j] + wPt[j];
                    gg = b + temp;
                    cc = temp + BSIG0(bb) + MAJ(bb, aa, a);
                    j++;

                    temp = e + BSIG1(gg) + CH(gg, ff, ee) + kPt[j] + wPt[j];
                    hh = a + temp;
                    dd = temp + BSIG0(cc) + MAJ(cc, bb, aa);
                    j++;

                    temp = ee + BSIG1(hh) + CH(hh, gg, ff) + kPt[j] + wPt[j];
                    h = aa + temp;
                    d = temp + BSIG0(dd) + MAJ(dd, cc, bb);
                    j++;

                    temp = ff + BSIG1(h) + CH(h, hh, gg) + kPt[j] + wPt[j];
                    g = bb + temp;
                    c = temp + BSIG0(d) + MAJ(d, dd, cc);
                    j++;

                    temp = gg + BSIG1(g) + CH(g, h, hh) + kPt[j] + wPt[j];
                    f = cc + temp;
                    b = temp + BSIG0(c) + MAJ(c, d, dd);
                    j++;

                    temp = hh + BSIG1(f) + CH(f, g, h) + kPt[j] + wPt[j];
                    e = dd + temp;
                    a = temp + BSIG0(b) + MAJ(b, c, d);
                    j++;
                }
            }

            hPt[0] += a;
            hPt[1] += b;
            hPt[2] += c;
            hPt[3] += d;
            hPt[4] += e;
            hPt[5] += f;
            hPt[6] += g;
            hPt[7] += h;
        }



        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private uint CH(uint x, uint y, uint z)
        {
            // (x & y) ^ ((~x) & z);
            return z ^ (x & (y ^ z)); //TODO: find mathematical proof for this change
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private uint MAJ(uint x, uint y, uint z)
        {
            // (x & y) ^ (x & z) ^ (y & z);
            return (x & y) | (z & (x | y)); //TODO: find mathematical proof for this change
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private uint BSIG0(uint x)
        {
            // ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22);
            return (x >> 2 | x << 30) ^ (x >> 13 | x << 19) ^ (x >> 22 | x << 10);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private uint BSIG1(uint x)
        {
            // ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25);
            return (x >> 6 | x << 26) ^ (x >> 11 | x << 21) ^ (x >> 25 | x << 7);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private uint SSIG0(uint x)
        {
            // ROTR(x, 7) ^ ROTR(x, 18) ^ (x >> 3);
            return (x >> 7 | x << 25) ^ (x >> 18 | x << 14) ^ (x >> 3);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private uint SSIG1(uint x)
        {
            // ROTR(x, 17) ^ ROTR(x, 19) ^ (x >> 10);
            return (x >> 17 | x << 15) ^ (x >> 19 | x << 13) ^ (x >> 10);
        }

        //private uint ROTR(uint x, int n)
        //{
        //    return (x >> n) | (x << (32 - n));
        //}

        //private uint ROTL(uint x, int n)
        //{
        //    return (x << n) | (x >> (32 - n));
        //}





        #region IDisposable Support
        private bool disposedValue = false;

        protected virtual void Dispose(bool disposing)
        {
            if (!disposedValue)
            {
                if (disposing)
                {
                    if (hashState != null)
                        Array.Clear(hashState, 0, hashState.Length);
                    hashState = null;

                    if (block != null)
                        Array.Clear(block, 0, block.Length);
                    block = null;

                    if (w != null)
                        Array.Clear(w, 0, w.Length);
                    w = null;
                }

                disposedValue = true;
            }
        }

        /// <summary>
        /// Releases all resources used by the current instance of the <see cref="Sha256"/> class.
        /// </summary>
        public void Dispose()
        {
            Dispose(true);
        }
        #endregion
    }
}
