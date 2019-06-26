using System;

namespace LearnMining
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("Choose which miner to run, options are:");
            Console.WriteLine("1. Bitcoin miner (double SHA-256).");
            Console.WriteLine("2. Litecoin miner (scrypt).");

            int option = Helper.ReadInt(1, 2);

            IMiner miner = null;
            switch (option)
            {
                case 1:
                    miner = new DoubleSha256Miner();
                    break;
                case 2:
                    miner = new ScryptMiner();
                    break;
            }

            if (miner != null)
            {
                miner.Mine();
            }
            else
            {
                Console.WriteLine("Could not initialize miner...");
                Console.WriteLine("Exiting...");
            }

            Console.ReadLine();
        }

    }
}
