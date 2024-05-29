using System.Text.Json.Serialization;

namespace Umbraco.Commerce.PaymentProviders.PayPal.Api.Models
{
    public class PayPalPayment
    {
        [JsonPropertyName("id")]
        public string Id { get; set; }

        [JsonPropertyName("custom_id")]
        public string CustomId { get; set; }

        [JsonPropertyName("status")]
        public string Status { get; set; }

        [JsonPropertyName("amount")]
        public PayPalAmount Amount { get; set; }
    }
}