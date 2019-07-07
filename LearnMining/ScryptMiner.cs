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
            // from https://litecoin.info/index.php/Scrypt
            uint blockVersion = 0x01000000U;
            // Since litecoin is a copy of bitcoin it uses the same hash algorithm as bitcoin to report block "hashes"!
            // and does it in the same reverse order
            byte[] prvBlockHash = Helper.HexToBytes("279f6330ccbbb9103b9e3a5350765052081ddbae898f1ef6b8c64f3bcef715f6", true);
            byte[] merkle = Helper.HexToBytes("066b2a758399d5f19b5c6073d09b500d925982adc4b3edd352efe14667a8ca9f", true);
            uint blockTime = 0xb817bb4eU;
            uint nBits = 0xa78e011dU;
            uint startingNonce = 0x012d59d4U - 50_000U;


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

            //zeroCount /= 4; // now this is the number of UInt32 items in array that must be zero



            Console.WriteLine("Start mining the block...");
            Stopwatch watch = new Stopwatch();
            watch.Start();

            // This is the unoptimized algorithm to see the mining algorithm and the underlying cryptography used
            // This puts a lot of pressure on garbage collector since the internal arrays in each function is being discarded each loop
            // Also the scrypt class is slow on its own.
            
            // Next step we optimize this algorith and remove each class and combine them all together.

            Scrypt scr = new Scrypt(1024, 1, 1);

            byte[] header = new byte[80];
            header[0] = (byte)(blockVersion >> 24);
            header[1] = (byte)(blockVersion >> 16);
            header[2] = (byte)(blockVersion >> 8);
            header[3] = (byte)(blockVersion);

            Buffer.BlockCopy(prvBlockHash, 0, header, 4, 32);
            Buffer.BlockCopy(merkle, 0, header, 36, 32);

            header[68] = (byte)(blockTime >> 24);
            header[69] = (byte)(blockTime >> 16);
            header[70] = (byte)(blockTime >> 8);
            header[71] = (byte)(blockTime);

            header[72] = (byte)(nBits >> 24);
            header[73] = (byte)(nBits >> 16);
            header[74] = (byte)(nBits >> 8);
            header[75] = (byte)(nBits);

            header[76] = (byte)(startingNonce >> 24);
            header[77] = (byte)(startingNonce >> 16);
            header[78] = (byte)(startingNonce >> 8);
            header[79] = (byte)(startingNonce);


            while (true)
            {
                byte[] result = scr.GetBytes(header, header, 32);

                bool enoughZero = true;
                for (int i = 0; i < zeroCount; i++)
                {
                    if (result[31 - i] != 0)
                    {
                        enoughZero = false;
                        break;
                    }
                }
                if (enoughZero)
                {
                    uint lastUint = (uint)(result[31 - zeroCount] | result[30 - zeroCount] << 8 | result[29 - zeroCount] << 16 | result[28 - zeroCount] << 24);
                    if (lastUint <= target)
                    {
                        break;
                    }
                }                

                startingNonce++;
                header[76] = (byte)(startingNonce >> 24);
                header[77] = (byte)(startingNonce >> 16);
                header[78] = (byte)(startingNonce >> 8);
                header[79] = (byte)(startingNonce);
            }


            watch.Stop();

            Console.WriteLine($"Ellapsed time is: {watch.Elapsed}");
            Helper.PrintHashrate(50000, watch.Elapsed.TotalSeconds);
        }

    }
}
