using System;
using System.Collections.Generic;
using System.Text;

namespace LearnMining
{
    public static class Extensions
    {
        public static uint SwapEndian(this uint val)
        {
            return (val >> 24) | (val << 24)
                 | ((val >> 8) & 0xff00) | ((val << 8) & 0xff0000); ;
        }


        public static int GetBitLength(this uint val)
        {
            int len = 0;
            while (val != 0)
            {
                val >>= 1;
                len++;
            }
            return len;
        }

        /// <summary>
        /// Concatinates two given byte arrays and returns a new byte array containing all the elements. 
        /// (~30 times faster than Linq)
        /// </summary>
        /// <exception cref="ArgumentNullException"/>
        /// <param name="firstArray">First set of bytes in the final array.</param>
        /// <param name="secondArray">Second set of bytes in the final array.</param>
        /// <returns>The concatinated array of bytes.</returns>
        public static byte[] ConcatFast(this byte[] firstArray, byte[] secondArray)
        {
            if (firstArray == null)
                throw new ArgumentNullException(nameof(firstArray), "First array can not be null!");
            if (secondArray == null)
                throw new ArgumentNullException(nameof(secondArray), "Second array can not be null!");


            byte[] result = new byte[firstArray.Length + secondArray.Length];
            Buffer.BlockCopy(firstArray, 0, result, 0, firstArray.Length);
            Buffer.BlockCopy(secondArray, 0, result, firstArray.Length, secondArray.Length);
            return result;
        }


        /// <summary>
        /// Creates a copy (clone) of the given byte array, will return null if the source was null instead of throwing.
        /// </summary>
        /// <param name="ba">Byte array to use</param>
        /// <returns>Copy of the given byte array</returns>
        public static byte[] CloneByteArray(this byte[] ba)
        {
            if (ba == null)
            {
                return null;
            }
            else
            {
                byte[] result = new byte[ba.Length];
                Buffer.BlockCopy(ba, 0, result, 0, ba.Length);
                return result;
            }
        }

    }
}
