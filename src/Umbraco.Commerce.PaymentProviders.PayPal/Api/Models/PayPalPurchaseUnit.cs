using System.Text.Json.Serialization;

namespace Umbraco.Commerce.PaymentProviders.PayPal.Api.Models
{
    public class PayPalPurchaseUnit : PayPalPurchaseUnitBase
    {
        [JsonPropertyName("id")]
        public string Id { get; set; }

        [JsonPropertyName("payments")]
        public PayPalPaymentCollection Payments { get; set; }
    }
}