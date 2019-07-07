using System;

namespace LearnMining.Cryptography
{
    public interface IHashFunction : IDisposable
    {
        /// <summary>
        /// Indicates whether the hash function should be performed twice on message.
        /// For example Double SHA256 that bitcoin uses.
        /// </summary>
        bool IsDouble { get; set; }

        /// <summary>
        /// Size of the hash result in bytes.
        /// </summary>
        int HashByteSize { get; }

        /// <summary>
        /// Size of the blocks used in each round.
        /// </summary>
        int BlockByteSize { get; }

        /// <summary>
        /// Computes the hash value for the specified byte array.
        /// </summary>
        /// <param name="data">The byte array to compute hash for</param>
        /// <returns>The computed hash</returns>
        byte[] ComputeHash(byte[] data);
    }
}
