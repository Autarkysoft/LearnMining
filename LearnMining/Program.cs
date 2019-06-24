using System;

namespace LearnMining
{
    class Program
    {
        static void Main(string[] args)
        {
            int option = Helper.ReadInt(1, 1);
            IMiner miner = null;
            switch (option)
            {
                case 1:
                    miner = new DoubleSha256Miner();
                    break;
            }

            if (miner != null)
            {
                miner.Mine();
                Console.ReadLine();
            }
            else
            {
                Console.WriteLine("Could not initialize miner...");
                Console.WriteLine("Exiting...");
            }
        }

    }
}
