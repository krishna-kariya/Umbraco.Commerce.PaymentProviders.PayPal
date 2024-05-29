using System.Text.Json.Serialization;

namespace Umbraco.Commerce.PaymentProviders.PayPal.Api.Models
{
    // https://developer.paypal.com/docs/api/webhooks/v1/#verify-webhook-signature

    public class PayPalVerifyWebhookSignatureResult
    {
        [JsonPropertyName("verification_status")]
        public string VerificationStatus { get; set; }
    }
}