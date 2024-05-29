using System.Text.Json.Serialization;

namespace Umbraco.Commerce.PaymentProviders.PayPal.Api.Models
{
    public class PayPalPurchaseUnitBase
    {
        [JsonPropertyName("custom_id")]
        public string CustomId { get; set; }

        [JsonPropertyName("description")]
        public string Description { get; set; }

        [JsonPropertyName("amount")]
        public PayPalAmount Amount { get; set; }
    }
}