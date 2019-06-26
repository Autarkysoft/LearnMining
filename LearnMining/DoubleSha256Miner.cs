using System;
using System.Diagnostics;
using System.Runtime.CompilerServices;

namespace LearnMining
{
    #region Explanation

    /*
     * Mining bitcoin is finding a hash that is smaller than a target compared as integers.
     * 
     * ***** The data *****
     * Data that is hahsed is the serialized block header which is always 80 bytes:
     * [version=4][previous block hash=32][merkle root=32][block time=4][nbits=4][nonce=4]=80 bytes in total
     * In this structure version and previous block hash and nbits can not change,
     * Merkle root changes with change in transactions that are in the block (add/remove tx, change in coinbase),
     * block time can change with seconds,
     * nonce is the main variable that is incremented on each hash.
     * 
     * 
     * ***** SHA-256 *****
     * Hash function used for bitcoin is SHA256 and is performed twice meaning: SHA256(SHA256(data))
     * 
     * SHA256 hash function splits data into blocks of 64 byte long and uses padding to to make them all 64 bytes.
     * So to hash 80 bytes (the first/inner hash), the data is split into 64+16 bytes:
     * The first 64 bytes is the first block and
     * since remainig 16 bytes is smaller than 56, only one additional block is needed with padding,
     * that makes total of 2 blocks.
     * To compute hash of block one, the inital values of HashState are the default Init() values of SHA256.
     * To compute hash of block two, the initial values of HashState are the result of previous compression.
     * 
     * The second/outer hash is performed on the result of previous hash (the HashState) that is 32 bytes
     * so we have one block that has 64 bytes (32 byte data + padding).
     * The HashState of this is the default Init() values of SHA256.
     * 
     * 
     * ***** The loop *****
     * The heart of the loop is incrementing nonce one by one and computing second block from first hash and the second hash,
     * that would be 2 calls to CompressBlock() instead of 3 since the result of first call (first block compression) doesn't change
     * there is no need to repeat it.
     * But since changing nonce may not always end up giving the desired hash, we need to change something else.
     * Here we increment BlockTime since it already takes a long time to compute the hash of full nonce.
     * In general the Merkle Root can also change which will require computing the first block compression again too.
     * 
     * 
     * */

    #endregion

    public class DoubleSha256Miner : IMiner
    {
        public unsafe void Mine()
        {
            uint blockVersion = 0x01000000U;
            // bitcoin reports hash hexes in reverse order hence the revarse=true in following two lines
            byte[] prvBlockHash = Helper.HexToBytes("000000006a625f06636b8bb6ac7b960a8d03705d1ace08b1a19da3fdcc99ddbd", true);
            byte[] merkle = Helper.HexToBytes("999e1c837c76a1b7fbb7e57baf87b309960f5ffefbf2a9b95dd890602272f644", true);
            uint blockTime = 0x5dbe6649U;
            uint nBits = 0xffff001dU;
            uint startingNonce = 0x05e0ed6dU - 50_000_000U;


            if (!Helper.AskYesNo("Run with default values"))
            {
                blockVersion = Helper.ReadUInt32("Block Version").SwapEndian();
                prvBlockHash = Helper.ReadHex("Previous Block Hash", 32, true);
                merkle = Helper.ReadHex("Merkle Root", 32, true);
                blockTime = Helper.ReadUInt32("Block Time").SwapEndian();
                nBits = Helper.ReadUInt32("NBits").SwapEndian();
                startingNonce = Helper.ReadUInt32("Nonce to start from").SwapEndian();
            }


            /*** Target ***/
            // if bits = XXYYYYYY then target = YYYYYY * 2^(8*(XX-3))
            // X * 2^k is the same as x << k
            int shift = 8 * ((byte)nBits - 3);
            // total is 256 bit, and 3*8 is the 3 bytes left in nBits that are shifted
            int zeroCount = (256 - shift - (3 * 8)) // this is number of zero bits
                / 8; // this is number of zero bytes
            uint target = nBits & 0xffffff00;
            for (int i = 1; i < 4; i++)
            {
                // if any of the bytes in remaining nBits is zero add 1 byte zero to zeroCount.
                // example: xxxx00 should add 1
                if ((byte)(target >> (i * 8)) == 0)
                {
                    zeroCount++;
                }
                else
                {
                    break;
                }
            }

            zeroCount /= 4; // now this is the number of UInt32 items in array that must be zero



            Console.WriteLine("Start mining the block...");
            Stopwatch watch = new Stopwatch();
            watch.Start();


            fixed (uint* blkPt1 = &block1[0], blkPt2 = &block2[0], blkPt3 = &block3[0])
            fixed (uint* hPt1 = &hashState1[0], hPt2 = &hashState2[0], hPt3 = &hashState3[0], wPt = &w[0])
            {
                /*** First block (64 byte) ***/
                // 4 byte block version
                blkPt1[0] = blockVersion;

                // 32 byte previous block hash
                fixed (byte* b = &prvBlockHash[0])
                {
                    blkPt1[1] = (uint)(b[0] << 24 | b[1] << 16 | b[2] << 8 | b[3]);
                    blkPt1[2] = (uint)(b[4] << 24 | b[5] << 16 | b[6] << 8 | b[7]);
                    blkPt1[3] = (uint)(b[8] << 24 | b[9] << 16 | b[10] << 8 | b[11]);
                    blkPt1[4] = (uint)(b[12] << 24 | b[13] << 16 | b[14] << 8 | b[15]);
                    blkPt1[5] = (uint)(b[16] << 24 | b[17] << 16 | b[18] << 8 | b[19]);
                    blkPt1[6] = (uint)(b[20] << 24 | b[21] << 16 | b[22] << 8 | b[23]);
                    blkPt1[7] = (uint)(b[24] << 24 | b[25] << 16 | b[26] << 8 | b[27]);
                    // Since max target is: 0x00000000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
                    // the final 32bits are always zero
                    // blkPt1[8] = 0;
                }

                // 28/32 byte MerkleRoot
                fixed (byte* b = &merkle[0])
                {
                    blkPt1[9] = (uint)(b[0] << 24 | b[1] << 16 | b[2] << 8 | b[3]);
                    blkPt1[10] = (uint)(b[4] << 24 | b[5] << 16 | b[6] << 8 | b[7]);
                    blkPt1[11] = (uint)(b[8] << 24 | b[9] << 16 | b[10] << 8 | b[11]);
                    blkPt1[12] = (uint)(b[12] << 24 | b[13] << 16 | b[14] << 8 | b[15]);
                    blkPt1[13] = (uint)(b[16] << 24 | b[17] << 16 | b[18] << 8 | b[19]);
                    blkPt1[14] = (uint)(b[20] << 24 | b[21] << 16 | b[22] << 8 | b[23]);
                    blkPt1[15] = (uint)(b[24] << 24 | b[25] << 16 | b[26] << 8 | b[27]);


                    /*** Perform first hash on block 1/2 ***/
                    Init(hPt1);
                    CompressBlock(blkPt1, hPt1, wPt);

                    /*** Second block (64 byte) ***/
                    // (final 4 bytes) 32/32 byte MerkleRoot
                    blkPt2[0] = (uint)(b[28] << 24 | b[29] << 16 | b[30] << 8 | b[31]); ;
                    blkPt2[0] = 0x831c9e99U;
                }


                // 4 byte BlockTime (index at 1)
                // will be incremented inside the block time loop
                blkPt2[1] = blockTime;

                // 4 byte NBits
                blkPt2[2] = nBits;

                // 4 byte Nonce (index at 3)
                // will be set and incremented inside the nonce loop

                // append length and padding:

                blkPt2[4] = 0b10000000_00000000_00000000_00000000U;
                // from 5 to 13 are zeros and are already set
                // message length is 80*8=640 bits so item at index 14 is also zero
                blkPt2[15] = 640;


                while (true)
                {
                    // second block (repeat hash of second block and second hash by incrementing nonce)
                    for (ulong nonce = startingNonce; nonce <= uint.MaxValue; nonce++)
                    {
                        blkPt2[3] = (uint)nonce;
                        // instead of Init() the hashstate for this block is previous hashstate
                        Buffer.BlockCopy(hashState1, 0, hashState2, 0, 32);
                        /*** Perform first hash on block 2/2 ***/
                        CompressBlock(blkPt2, hPt2, wPt);

                        // perform second hash
                        // Result of previous hash (hashState2[]) is now our new block. So copy it here:
                        blkPt3[0] = hPt2[0];
                        blkPt3[1] = hPt2[1];
                        blkPt3[2] = hPt2[2];
                        blkPt3[3] = hPt2[3];
                        blkPt3[4] = hPt2[4];
                        blkPt3[5] = hPt2[5];
                        blkPt3[6] = hPt2[6];
                        blkPt3[7] = hPt2[7]; // 8*4 = 32 byte hash result

                        blkPt3[8] = 0b10000000_00000000_00000000_00000000U; // 1 followed by 0 bits to fill pad1
                        //blkPt3[9] = 0;
                        //blkPt3[10] = 0;
                        //blkPt3[11] = 0;
                        //blkPt3[12] = 0;
                        //blkPt3[13] = 0;

                        // Message length for pad2, since message is the 32 byte result of previous hash, length is 256 bit
                        //blkPt3[14] = 0; 
                        blkPt3[15] = 256;

                        /*** Perform second hash on block 1/1 ***/
                        // Now initialize hashState to compute next round
                        Init(hPt3);
                        CompressBlock(blkPt3, hPt3, wPt);


                        // Check to see if the hash result is smaller than target
                        bool b = true;
                        for (int i = 0; i < zeroCount; i++)
                        {
                            if (hPt3[7 - i] != 0)
                            {
                                b = false;
                                break;
                            }
                        }
                        if (b && hPt3[7 - zeroCount] <= target)
                        {
                            watch.Stop();

                            Console.WriteLine($"success! nonce= {((uint)nonce).SwapEndian()}");
                            Console.WriteLine($"Ellapsed time is: {watch.Elapsed}");
                            Helper.PrintHashrate(nonce - startingNonce, watch.Elapsed.TotalSeconds);

                            return;
                        }
                    }


                    // incremented block time
                    blockTime = (blockTime.SwapEndian() + 1).SwapEndian();
                    blkPt2[1] = blockTime;

                    // Make sure nonce starts from zero
                    startingNonce = 0;
                }
            }
        }


        private unsafe void Init(uint* hPt)
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

        private unsafe void CompressBlock(uint* xPt, uint* hPt, uint* wPt)
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
            return z ^ (x & (y ^ z));
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private uint MAJ(uint x, uint y, uint z)
        {
            return (x & y) | (z & (x | y));
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private uint BSIG0(uint x)
        {
            return (x >> 2 | x << 30) ^ (x >> 13 | x << 19) ^ (x >> 22 | x << 10);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private uint BSIG1(uint x)
        {
            return (x >> 6 | x << 26) ^ (x >> 11 | x << 21) ^ (x >> 25 | x << 7);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private uint SSIG0(uint x)
        {
            return (x >> 7 | x << 25) ^ (x >> 18 | x << 14) ^ (x >> 3);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private uint SSIG1(uint x)
        {
            return (x >> 17 | x << 15) ^ (x >> 19 | x << 13) ^ (x >> 10);
        }


        private uint[] w = new uint[64];

        private readonly uint[] block1 = new uint[16];
        private readonly uint[] block2 = new uint[16];
        private readonly uint[] block3 = new uint[16];
        private readonly uint[] hashState1 = new uint[8];
        private readonly uint[] hashState2 = new uint[8];
        private readonly uint[] hashState3 = new uint[8];

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

    }
}
