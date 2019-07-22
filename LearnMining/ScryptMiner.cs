using System;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using LearnMining.Cryptography;

namespace LearnMining
{
    #region Explanation

    /*
     * Mining litecoin is similar to mining bitcoin except it uses scrypt KDF as its hash algorithm
     * 
     * ***** The data *****
     * Data is the same as bitcoin's
     * 
     * 
     * ***** scrypt *****
     * Hash function used for litecoin is scrypt which is an expensive key derivation function.
     * Scrypt at heart uses PBKDF2 (RFC-8018) and its own internal block mixing algorithm.
     * The password and salt of scrypt which then are passed to first call to PBKDF2 are both the same the serialized (80 byte) header.
     * N or costParam is 1024
     * r or blockSizeFactor is 1
     * p or parallelization is 1
     * dkLen which is the hash result is set to 32
     * 
     * 
     * ***** PBKDF2 (RFC-8018) *****
     * Password (the 80 byte header) is used as HMAC's key.
     * Salt (the same 80 byte header) which is internally appended with 4 bytes indicating the KDF's block number 
     * and is given to HMAC function for computation and is repeated iteration (p*128*r=128 passed from scrypt) times.
     * 
     * 
     * ***** HMAC-SHA (RFC-2104) *****
     * Key: if the key is bigger than underlying hash function's block size then it must be hashed first to be reduced to block size.
     *      Then key (or result of hash) is padded with zeros to become block size long.
     *      Finally one inner pad and one outer pad is defined by XOR-ing key with 0x36 and 0x5c respectively.
     * HMAC result is the result of: SHA(outerPad | SHA(innerPad | data))
     * Since key is 80 bytes, it must be hashed before using as key.
     * so SHA-256 (the underlying hash function) is called 3 times, one for key and twice for the final result.
     * First with 80 bytes
     * second with 64+80 bytes
     * third with 64+32 bytes
     * 
     * 
     * ***** The loop *****
     * Same incrementation as bitcoin.
     * 
     * 
     * 
     * */

    #endregion

    public class ScryptMiner : IMiner
    {
        public unsafe void Mine()
        {
            Console.WriteLine();
            Console.WriteLine("Scrypt miner is selected.");
            Console.WriteLine("Additional links:");
            Console.WriteLine("   Mining litecoin: https://litecoin.info/index.php/Scrypt");
            Console.WriteLine("   scrypt: https://tools.ietf.org/html/rfc7914");
            Console.WriteLine("   PBKDF2: https://tools.ietf.org/html/rfc8018");
            Console.WriteLine("   HMAC-SHA: https://tools.ietf.org/html/rfc2104");
            Console.WriteLine();

            // from https://litecoin.info/index.php/Scrypt
            uint blockVersion = 0x01000000U;
            // Since litecoin is a copy of bitcoin it uses the same hash algorithm as bitcoin to report block "hashes"!
            // and does it in the same reverse order
            byte[] prvBlockHash = Helper.HexToBytes("279f6330ccbbb9103b9e3a5350765052081ddbae898f1ef6b8c64f3bcef715f6", true);
            byte[] merkle = Helper.HexToBytes("066b2a758399d5f19b5c6073d09b500d925982adc4b3edd352efe14667a8ca9f", true);
            uint blockTime = 0xb817bb4eU;
            uint nBits = 0xa78e011dU;
            uint startingNonce = 0x012d59d4U - 100_000U;


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
            uint[] target = Helper.ToTarget(nBits);


            Console.WriteLine("Start mining the block...");
            Stopwatch watch = new Stopwatch();
            watch.Start();

            // To compute the PoW hash (result of scrypt) we start from the bottom and come up
            // Scrypt first calls PBKDF2 with password and salt (both = 80 byte header)
            // PBKDF2 uses HMAC-SHA256 with its key set to password and the data is (salt | block_number)=84 byte
            //        block count is dkLen/hmac_outputLen = p*128*r/32 = 4 (HMAC needs to be called 4 times)
            //        iteration is 1 so there is no loop inside F() function
            // HMAC-SHA256 key should be smaller than underlying hash block size (here=64) and if it is bigger it will be hashed
            // HMAC-SHA256 hash of a data is result of H(opad|H(ipad|data))
            //             pads length are block size
            //             inner hash is hash of 64+84=148 bytes => 3 SHA256 blocks
            //             outer hash is hash of 64+32=96 bytes => 2 SHA256 blocks
            //             the data here is the same first 80 bytes with last 4 bytes changing

            // compute hash of header for HMAC key
            uint[] hmac_key_hashState1 = new uint[8];
            uint[] hmac_key_hashState2 = new uint[8];
            uint[] hmac_key_block1 = new uint[16];
            uint[] hmac_key_block2 = new uint[16];

            uint[] pbkdf2_hmac_block1 = new uint[16];
            uint[] pbkdf2_hmac_block2 = new uint[16];
            uint[] pbkdf2_hmac_block3 = new uint[16];
            uint[] pbkdf2_hmac_block4 = new uint[16];
            uint[] pbkdf2_hmac_block5 = new uint[16];

            uint[] ipad = new uint[16];
            uint[] opad = new uint[16];

            // The first derived key used in scrypt is the result of PBKDF2 of length p*128*r (=128 byte here = 32 uint)
            // The key is the result of blockCount times HMAC-SHA256 so directly copy HMAC results aka hashstates here
            uint[] scryptDk = new uint[32];
            uint[] scryptV = new uint[1 * 128 * 1024 / 4]; // r*128*n /4  =32,768


            fixed (byte* prvBHPt = &prvBlockHash[0], mrklPt = &merkle[0])
            fixed (uint* wPt = &w[0])
            fixed (uint* hm_k_hsPt1 = &hmac_key_hashState1[0], hm_k_hsPt2 = &hmac_key_hashState2[0])
            fixed (uint* hm_k_blkPt1 = &hmac_key_block1[0], hm_k_blkPt2 = &hmac_key_block2[0])

            fixed (uint* p_hm_hsPt1 = &scryptDk[0], p_hm_hsPt2 = &scryptDk[8], p_hm_hsPt3 = &scryptDk[16], p_hm_hsPt4 = &scryptDk[24])
            fixed (uint* p_hm_blkPt1 = &pbkdf2_hmac_block1[0], p_hm_blkPt2 = &pbkdf2_hmac_block2[0], p_hm_blkPt3 = &pbkdf2_hmac_block3[0], p_hm_blkPt4 = &pbkdf2_hmac_block4[0], p_hm_blkPt5 = &pbkdf2_hmac_block5[0])
            fixed (uint* p_ipdPt = &ipad[0], p_opdPt = &opad[0])

            fixed (uint* scr_dkPt = &scryptDk[0], vPt = &scryptV[0])
            fixed (uint* tarPt = &target[0])
            {
                hm_k_blkPt1[0] = blockVersion;

                // 32 byte previous block hash
                hm_k_blkPt1[1] = (uint)(prvBHPt[0] << 24 | prvBHPt[1] << 16 | prvBHPt[2] << 8 | prvBHPt[3]);
                hm_k_blkPt1[2] = (uint)(prvBHPt[4] << 24 | prvBHPt[5] << 16 | prvBHPt[6] << 8 | prvBHPt[7]);
                hm_k_blkPt1[3] = (uint)(prvBHPt[8] << 24 | prvBHPt[9] << 16 | prvBHPt[10] << 8 | prvBHPt[11]);
                hm_k_blkPt1[4] = (uint)(prvBHPt[12] << 24 | prvBHPt[13] << 16 | prvBHPt[14] << 8 | prvBHPt[15]);
                hm_k_blkPt1[5] = (uint)(prvBHPt[16] << 24 | prvBHPt[17] << 16 | prvBHPt[18] << 8 | prvBHPt[19]);
                hm_k_blkPt1[6] = (uint)(prvBHPt[20] << 24 | prvBHPt[21] << 16 | prvBHPt[22] << 8 | prvBHPt[23]);
                hm_k_blkPt1[7] = (uint)(prvBHPt[24] << 24 | prvBHPt[25] << 16 | prvBHPt[26] << 8 | prvBHPt[27]);
                hm_k_blkPt1[8] = (uint)(prvBHPt[28] << 24 | prvBHPt[29] << 16 | prvBHPt[30] << 8 | prvBHPt[31]);

                // 28/32 byte MerkleRoot
                hm_k_blkPt1[9] = (uint)(mrklPt[0] << 24 | mrklPt[1] << 16 | mrklPt[2] << 8 | mrklPt[3]);
                hm_k_blkPt1[10] = (uint)(mrklPt[4] << 24 | mrklPt[5] << 16 | mrklPt[6] << 8 | mrklPt[7]);
                hm_k_blkPt1[11] = (uint)(mrklPt[8] << 24 | mrklPt[9] << 16 | mrklPt[10] << 8 | mrklPt[11]);
                hm_k_blkPt1[12] = (uint)(mrklPt[12] << 24 | mrklPt[13] << 16 | mrklPt[14] << 8 | mrklPt[15]);
                hm_k_blkPt1[13] = (uint)(mrklPt[16] << 24 | mrklPt[17] << 16 | mrklPt[18] << 8 | mrklPt[19]);
                hm_k_blkPt1[14] = (uint)(mrklPt[20] << 24 | mrklPt[21] << 16 | mrklPt[22] << 8 | mrklPt[23]);
                hm_k_blkPt1[15] = (uint)(mrklPt[24] << 24 | mrklPt[25] << 16 | mrklPt[26] << 8 | mrklPt[27]);


                /*** Perform first hash on block 1/2 ***/
                Init(hm_k_hsPt1);
                CompressBlock(hm_k_blkPt1, hm_k_hsPt1, wPt);

                /*** Second block (64 byte) ***/
                // (final 4 bytes) 32/32 byte MerkleRoot
                hm_k_blkPt2[0] = (uint)(mrklPt[28] << 24 | mrklPt[29] << 16 | mrklPt[30] << 8 | mrklPt[31]);

                // 4 byte BlockTime (index at 1)
                // will be incremented inside the block time loop
                hm_k_blkPt2[1] = blockTime;

                // 4 byte NBits
                hm_k_blkPt2[2] = nBits;

                // 4 byte Nonce (index at 3)
                // will be set and incremented inside the nonce loop

                // append length and padding:

                hm_k_blkPt2[4] = 0b10000000_00000000_00000000_00000000U;
                // from 5 to 13 are zeros and are already set
                // message length is 80*8=640 bits so item at index 14 is also zero
                hm_k_blkPt2[15] = 640;


                while (true)
                {
                    // second block (repeat hash of second block and second hash by incrementing nonce)
                    for (ulong nonce = startingNonce; nonce <= uint.MaxValue; nonce++)
                    {
                        hm_k_blkPt2[3] = (uint)nonce;
                        // instead of Init() the hashstate for this block is previous hashstate
                        Buffer.BlockCopy(hmac_key_hashState1, 0, hmac_key_hashState2, 0, 32);
                        /*** Perform first hash on block 2/2 ***/
                        CompressBlock(hm_k_blkPt2, hm_k_hsPt2, wPt);

                        /**** HMAC key is set ****/

                        // pbkdf2 dklen = 128
                        // blockCount = 4 => for i=1, 2, 3, 4
                        // i = 1
                        // opad and ipad are 64 byte 
                        // Concatinate ipda with data that is 80+4 = 148 byte => compute SHA256 (3 blocks)
                        // concat 64 + 32 = 96 byte => compute SHA256 (2 blocks)

                        // First block = ipad = 0x36 ^ key (key is 32 bytes)
                        p_hm_blkPt1[0] = 0x36363636U ^ hm_k_hsPt2[0];
                        p_hm_blkPt1[1] = 0x36363636U ^ hm_k_hsPt2[1];
                        p_hm_blkPt1[2] = 0x36363636U ^ hm_k_hsPt2[2];
                        p_hm_blkPt1[3] = 0x36363636U ^ hm_k_hsPt2[3];
                        p_hm_blkPt1[4] = 0x36363636U ^ hm_k_hsPt2[4];
                        p_hm_blkPt1[5] = 0x36363636U ^ hm_k_hsPt2[5];
                        p_hm_blkPt1[6] = 0x36363636U ^ hm_k_hsPt2[6];
                        p_hm_blkPt1[7] = 0x36363636U ^ hm_k_hsPt2[7];
                        p_hm_blkPt1[8] = 0x36363636U;
                        p_hm_blkPt1[9] = 0x36363636U;
                        p_hm_blkPt1[10] = 0x36363636U;
                        p_hm_blkPt1[11] = 0x36363636U;
                        p_hm_blkPt1[12] = 0x36363636U;
                        p_hm_blkPt1[13] = 0x36363636U;
                        p_hm_blkPt1[14] = 0x36363636U;
                        p_hm_blkPt1[15] = 0x36363636U;

                        uint[] hashState1 = new uint[8];
                        fixed (uint* hs1 = &hashState1[0])
                        {
                            Init(hs1);
                            CompressBlock(p_hm_blkPt1, hs1, wPt);
                        }

                        // Second block = first 64 bytes of header which is already set in first block for HMAC key calculation
                        uint[] hashState2 = new uint[8];
                        fixed (uint* hs2 = &hashState2[0])
                        {
                            Buffer.BlockCopy(hashState1, 0, hashState2, 0, 32);
                            CompressBlock(hm_k_blkPt1, hs2, wPt);
                        }

                        // Third block = remaining 20 (80+4-64) bytes of header + SHA256 padding
                        // this block is the same as the block for key calculation but it has additioanl 4 bytes (PBKDF2 block number)
                        uint[] hashState3 = new uint[8];
                        uint[] hashState_outer1 = new uint[8];
                        fixed (uint* hs3 = &hashState3[0])
                        {
                            for (uint blockNumber = 1; blockNumber <= 4; blockNumber++)
                            {
                                Buffer.BlockCopy(hashState2, 0, hashState3, 0, 32);

                                p_hm_blkPt3[0] = hm_k_blkPt2[0];//merkle
                                p_hm_blkPt3[1] = hm_k_blkPt2[1];//blockTime
                                p_hm_blkPt3[2] = hm_k_blkPt2[2];//NBits
                                p_hm_blkPt3[3] = hm_k_blkPt2[3];//nonce

                                p_hm_blkPt3[4] = blockNumber;//block number

                                p_hm_blkPt3[5] = 0b10000000_00000000_00000000_00000000U; //SHA256 pad:
                                p_hm_blkPt3[15] = 1184; // length = 64+80+4=148 *8 = 1184

                                CompressBlock(p_hm_blkPt3, hs3, wPt);

                                /**** opad | hashstate ****/
                                // 4th block = opad = 0x5c ^ key (key is 32 bytes)
                                p_hm_blkPt4[0] = 0x5c5c5c5cU ^ hm_k_hsPt2[0];
                                p_hm_blkPt4[1] = 0x5c5c5c5cU ^ hm_k_hsPt2[1];
                                p_hm_blkPt4[2] = 0x5c5c5c5cU ^ hm_k_hsPt2[2];
                                p_hm_blkPt4[3] = 0x5c5c5c5cU ^ hm_k_hsPt2[3];
                                p_hm_blkPt4[4] = 0x5c5c5c5cU ^ hm_k_hsPt2[4];
                                p_hm_blkPt4[5] = 0x5c5c5c5cU ^ hm_k_hsPt2[5];
                                p_hm_blkPt4[6] = 0x5c5c5c5cU ^ hm_k_hsPt2[6];
                                p_hm_blkPt4[7] = 0x5c5c5c5cU ^ hm_k_hsPt2[7];
                                p_hm_blkPt4[8] = 0x5c5c5c5cU;
                                p_hm_blkPt4[9] = 0x5c5c5c5cU;
                                p_hm_blkPt4[10] = 0x5c5c5c5cU;
                                p_hm_blkPt4[11] = 0x5c5c5c5cU;
                                p_hm_blkPt4[12] = 0x5c5c5c5cU;
                                p_hm_blkPt4[13] = 0x5c5c5c5cU;
                                p_hm_blkPt4[14] = 0x5c5c5c5cU;
                                p_hm_blkPt4[15] = 0x5c5c5c5cU;


                                fixed (uint* hsO1 = &hashState_outer1[0])
                                {
                                    Init(hsO1);
                                    CompressBlock(p_hm_blkPt4, hsO1, wPt);
                                }

                                // 5th block = hash of hashstate of innder hash
                                p_hm_blkPt5[0] = hs3[0];
                                p_hm_blkPt5[1] = hs3[1];
                                p_hm_blkPt5[2] = hs3[2];
                                p_hm_blkPt5[3] = hs3[3];
                                p_hm_blkPt5[4] = hs3[4];
                                p_hm_blkPt5[5] = hs3[5];
                                p_hm_blkPt5[6] = hs3[6];
                                p_hm_blkPt5[7] = hs3[7];

                                p_hm_blkPt5[8] = 0b10000000_00000000_00000000_00000000U;
                                p_hm_blkPt5[15] = 768; // 64+32 = 96 *8 = 768 bit

                                uint[] hashState_outer2 = new uint[8];
                                fixed (uint* hsO2 = &hashState_outer2[0])
                                {
                                    Buffer.BlockCopy(hashState_outer1, 0, hashState_outer2, 0, 32);
                                    CompressBlock(p_hm_blkPt5, hsO2, wPt);
                                }

                                Buffer.BlockCopy(hashState_outer2, 0, scryptDk, ((int)blockNumber - 1) * 32, 32);
                            }

                            for (int i = 0; i < scryptDk.Length; i++)
                            {
                                scryptDk[i] = scryptDk[i].SwapEndian();
                            }
                        }


                        /****  Scrypt  ****/
                        // set V
                        Buffer.BlockCopy(scryptDk, 0, scryptV, 0, 128);

                        uint* srcPt = vPt;
                        uint* dstPt = vPt + 32 /*blockSizeUint*/;

                        // Set V1 to final V(n-1)
                        for (int i = 0; i < 1023; i++)
                        {
                            BlockMix(srcPt, dstPt);
                            srcPt += 32 /*blockSizeUint*/;
                            dstPt += 32 /*blockSizeUint*/;
                        }

                        uint[] x = new uint[32];
                        // We need a clone of x becasue BlockMix function needs to use the same fixed values of x while setting the result in output
                        uint[] xClone = new uint[32];
                        fixed (uint* xPt = &x[0], xClPt = &xClone[0])
                        {
                            // Perform BlockMix on X to update its result
                            BlockMix(srcPt, xPt);

                            for (int i = 0; i < 1024; i++)
                            {
                                // *** Integerify ***
                                // j = Integerify (X) mod N
                                //      Integerify (B[0] ... B[2 * r - 1]) is defined as 
                                //      the result of interpreting B[2 * r - 1] as a little-endian integer.

                                // Interpret (B[2 * r - 1]) in (B[0] ... B[2 * r - 1]) as a little-endian integer and compute mod N
                                // This means taking the last 64 byte chunk from the block
                                // Since the conversion from data to uint[] is done in little-endian order, the result is already in correct endian
                                // and we need the least significat bytes (first item in that chunk) 
                                //                                                  => index = B.Length - 16

                                // B (or x) always has blockSize(=r*128) items in byte[] or blockSizeUint(=r*32) items in uint[]
                                // last 64 bytes = last 16*4 byte or 16 uint items in its uint[]

                                // Since value of N (costParam) is an integer set in constructor, it will always be smaller than a uint
                                // so mod N can be calculated with only 1 item from uint[] and that is the last item

                                // Since N is a power of 2, calculating mod N is a simple bitwise AND with (N-1)
                                // The final cast to int doesn't overflow since N is an int and mod N is always smaller than N.
                                int j = (int)(xPt[x.Length - 16] & 1023);
                                XOR(xPt, vPt + (j * 32), x.Length);

                                BlockMix(xPt, xClPt);
                                Buffer.BlockCopy(xClone, 0, x, 0, 128);
                            }
                        }

                        // Now that this block is "mixed" we have the expensive salt for second call to PBKDF2
                        // it just needs to be converted back to byte[]
                        Buffer.BlockCopy(x, 0, scryptDk, 0, 128);

                        /**** Final PBKDF2 ****/
                        // pass is the same header, salt is the new 128 "mixed" bytes, dkLen is 32
                        // with 32 byte dkLen we only have 1 block
                        // so HMAC-SHA256 with the same key is performed 1 time with blockNumber=1 on 128+4 byte data
                        // this means 
                        // Concatinate ipad with data that is 128+4 = 196 byte => compute SHA256 (4 blocks)
                        // concat 64 + 32 = 96 byte => compute SHA256 (2 blocks)

                        // The first block here is the same ipad as before since key didn't change (hashState1)
                        // second block is first 64 bytes of scryptDk
                        // third block is second 64 bytes of scryptDk
                        // forth block is 4 byte blocknumber(=1) + SHA256 paddings
                        uint[] hashStateFinal2 = new uint[8];
                        Buffer.BlockCopy(hashState1, 0, hashStateFinal2, 0, 32);

                        uint[] finalBlockInner = new uint[16];
                        uint[] outerBlock1 = new uint[16];
                        uint[] outerBlock2 = new uint[16];

                        for (int i = 0; i < scryptDk.Length; i++)
                        {
                            scryptDk[i] = scryptDk[i].SwapEndian();
                        }

                        fixed (uint* hsPt2 = &hashStateFinal2[0], fbInPt = &finalBlockInner[0], obPt2 = &outerBlock2[0])
                        {
                            CompressBlock(scr_dkPt, hsPt2, wPt);
                            CompressBlock(scr_dkPt + 16, hsPt2, wPt);

                            fbInPt[0] = 1U; // blockNumber
                            fbInPt[1] = 0b10000000_00000000_00000000_00000000U; // SHA256 pad
                            fbInPt[15] = 1568; // length = 64+128+4=196 *8= 1568 bit

                            CompressBlock(fbInPt, hsPt2, wPt);


                            /**** opad | hashstate ****/
                            // block1 = opad = 0x5c ^ key (key is 32 bytes)
                            // this is already calculated in hashState_outer1

                            // outer block 2 = hash of hashstate of innder hash
                            obPt2[0] = hsPt2[0];
                            obPt2[1] = hsPt2[1];
                            obPt2[2] = hsPt2[2];
                            obPt2[3] = hsPt2[3];
                            obPt2[4] = hsPt2[4];
                            obPt2[5] = hsPt2[5];
                            obPt2[6] = hsPt2[6];
                            obPt2[7] = hsPt2[7];

                            obPt2[8] = 0b10000000_00000000_00000000_00000000U;
                            obPt2[15] = 768; // 64+32 = 96 *8 = 768 bit

                            uint[] hashState_outer2 = new uint[8];
                            fixed (uint* hsO2 = &hashState_outer2[0])
                            {
                                Buffer.BlockCopy(hashState_outer1, 0, hashState_outer2, 0, 32);
                                CompressBlock(obPt2, hsO2, wPt);

                                if (Helper.CompareTarget(hsO2, tarPt, hashState3.Length))
                                {
                                    watch.Stop();

                                    Console.WriteLine($"success! nonce= {((uint)nonce).SwapEndian()}");
                                    Console.WriteLine($"Ellapsed time is: {watch.Elapsed}");
                                    Helper.PrintHashrate(nonce - startingNonce, watch.Elapsed.TotalSeconds);

                                    return;
                                }
                            }
                        }
                    }


                    // incremented block time
                    blockTime = (blockTime.SwapEndian() + 1).SwapEndian();
                    hm_k_blkPt2[1] = blockTime;

                    // Make sure nonce starts from zero
                    startingNonce = 0;
                }
            }
        }






        private uint[] w = new uint[64];
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



        uint[] blockMixBuffer = new uint[16]; // (64/4)=16
        private unsafe void BlockMix(uint* srcPt, uint* dstPt)
        {
            // Treat block as 2r 64 byte chunks
            fixed (uint* xPt = &blockMixBuffer[0])
            {
                Copy64(srcPt + 16 /*blockSizeUint - 16*/, xPt);

                // loop is for i=0 to 2*r-1
                // result (B') is Y[0], Y[2], ..., Y[2 * r - 2], Y[1], Y[3], ..., Y[2 * r - 1]
                // since r=1 we have 2 parts Y[0] and Y[1]
                XOR(xPt, srcPt, 16);
                Salsa20_8(xPt);
                Copy64(xPt, dstPt);

                XOR(xPt, srcPt + 16, 16);
                Salsa20_8(xPt);
                Copy64(xPt, dstPt + 16);
            }
        }

        private unsafe void XOR(uint* first, uint* second, int uLen)
        {
            for (int i = 0; i < uLen; i++)
            {
                first[i] ^= second[i];
            }

        }

        private unsafe void Salsa20_8(uint* block)
        {
            // Salsa is performed on a block with 64 byte length (16 uint)
            uint x0 = block[0];
            uint x1 = block[1];
            uint x2 = block[2];
            uint x3 = block[3];
            uint x4 = block[4];
            uint x5 = block[5];
            uint x6 = block[6];
            uint x7 = block[7];
            uint x8 = block[8];
            uint x9 = block[9];
            uint x10 = block[10];
            uint x11 = block[11];
            uint x12 = block[12];
            uint x13 = block[13];
            uint x14 = block[14];
            uint x15 = block[15];

            // Inside the loop value of `i` is not used, the loop is repetition of the process 4 times
            // there is no point in doing it as RFC documents:
            // for (int i = 8; i > 0; i -= 2) 
            // i+=2 or the reverse is only used when the `Rounds` (here=8) is unknown 
            // in which case a double round on each iteration is performed.

            for (int i = 0; i < 4; i++)
            {
                x4 ^= R(x0 + x12, 7); x8 ^= R(x4 + x0, 9);
                x12 ^= R(x8 + x4, 13); x0 ^= R(x12 + x8, 18);
                x9 ^= R(x5 + x1, 7); x13 ^= R(x9 + x5, 9);
                x1 ^= R(x13 + x9, 13); x5 ^= R(x1 + x13, 18);
                x14 ^= R(x10 + x6, 7); x2 ^= R(x14 + x10, 9);
                x6 ^= R(x2 + x14, 13); x10 ^= R(x6 + x2, 18);
                x3 ^= R(x15 + x11, 7); x7 ^= R(x3 + x15, 9);
                x11 ^= R(x7 + x3, 13); x15 ^= R(x11 + x7, 18);

                x1 ^= R(x0 + x3, 7); x2 ^= R(x1 + x0, 9);
                x3 ^= R(x2 + x1, 13); x0 ^= R(x3 + x2, 18);
                x6 ^= R(x5 + x4, 7); x7 ^= R(x6 + x5, 9);
                x4 ^= R(x7 + x6, 13); x5 ^= R(x4 + x7, 18);
                x11 ^= R(x10 + x9, 7); x8 ^= R(x11 + x10, 9);
                x9 ^= R(x8 + x11, 13); x10 ^= R(x9 + x8, 18);
                x12 ^= R(x15 + x14, 7); x13 ^= R(x12 + x15, 9);
                x14 ^= R(x13 + x12, 13); x15 ^= R(x14 + x13, 18);
            }

            block[0] += x0;
            block[1] += x1;
            block[2] += x2;
            block[3] += x3;
            block[4] += x4;
            block[5] += x5;
            block[6] += x6;
            block[7] += x7;
            block[8] += x8;
            block[9] += x9;
            block[10] += x10;
            block[11] += x11;
            block[12] += x12;
            block[13] += x13;
            block[14] += x14;
            block[15] += x15;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private uint R(uint a, int b)
        {
            return unchecked((a << b) | (a >> (32 - b)));
        }

        private unsafe void Copy64(uint* src, uint* dst)
        {
            for (int i = 0; i < 16; i += 2)
            {
                *(ulong*)(dst + i) = *(ulong*)(src + i);
            }
        }


    }
}
