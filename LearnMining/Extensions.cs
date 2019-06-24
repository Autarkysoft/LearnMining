using System;
using System.Collections.Generic;
using System.Text;

namespace LearnMining
{
  public static  class Extensions
    {
        public static uint SwapEndian(this uint val)
        {
            return (val >> 24) | (val << 24) 
                 | ((val >> 8) & 0xff00) | ((val << 8) & 0xff0000); ;
        }


        public static int GetBitLength(this uint val)
        {
            int len = 0;
            while (val !=0)
            {
                val >>= 1;
                len++;
            }
            return len;
        }

    }
}
