using System;
using System.Diagnostics;
using System.Runtime.CompilerServices;

namespace LearnMining
{
    #region Explanation

    /*
     * Mining litecoin is is exactly similar to mining bitcoin except it uses scrypt KDF as its hash algorithm
     * 
     * ***** The data *****
     * Data is the same as bitcoin's
     * 
     * ***** scrypt *****
     * Hash function used for litecoin is scrypt which is an expensive key derivation function.
     * Scrypt at heart uses PBKDF2 (RFC-8018) and HMAC-SHA-256 while it has its own internal block mixing algorithm.
     * 
     * 
     * ***** The loop *****
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
            byte[] prvBlockHash = Helper.HexToBytes("05e9a54b7f65b46864bc90f55d67cccd8b6404a02f5e064a6df69282adf6e2e5 ", true);
            byte[] merkle = Helper.HexToBytes("f7f953b0632b25b099858b717bb7b24084148cfa841a89f106bc6b655b18d2ed ", true);
            uint blockTime = 0x1a19bb4eU;
            uint nBits = 0xa78e011dU;
            uint startingNonce = 0x42a14695U - 50_000_000U;


            Console.WriteLine("Coming soon!");



        }

    }
}
