namespace JWT_Ref.Models
{
    public class Response<T> where T : class
    {
        public string? Status { get; set; }
        public string? Message { get; set; }
        public T Result { get; set; }
    }
}
