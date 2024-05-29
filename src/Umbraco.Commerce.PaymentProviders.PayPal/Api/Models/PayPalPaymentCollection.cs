using System.Text.Json.Serialization;

namespace Umbraco.Commerce.PaymentProviders.PayPal.Api.Models
{
    public class PayPalPaymentCollection
    {
        [JsonPropertyName("authorizations")]
        public PayPalAuthorizationPayment[] Authorizations { get; set; }

        [JsonPropertyName("captures")]
        public PayPalCapturePayment[] Captures { get; set; }

        [JsonPropertyName("refunds")]
        public PayPalRefundPayment[] Refunds { get; set; }

    }
}