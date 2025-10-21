namespace FirebaseAuth.NET.Storage
{
    public interface ISecureStorage
    {
        Task SetAsync(string k, string v);
        Task<string?> GetAsync(string k);
        void Remove(string k);
    }
}
