using System.Text.Json.Serialization;

namespace Umbraco.Commerce.PaymentProviders.PayPal.Api.Models
{
    // https://developer.paypal.com/docs/api/webhooks/v1/#verify-webhook-signature

    public class PayPalVerifyWebhookSignatureRequest
    {
        [JsonPropertyName("auth_algo")]
        public string AuthAlgorithm { get; set; }

        [JsonPropertyName("cert_url")]
        public string CertUrl { get; set; }

        [JsonPropertyName("transmission_id")]
        public string TransmissionId { get; set; }

        [JsonPropertyName("transmission_sig")]
        public string TransmissionSignature { get; set; }

        [JsonPropertyName("transmission_time")]
        public string TransmissionTime { get; set; }

        [JsonPropertyName("webhook_id")]
        public string WebhookId { get; set; }

        [JsonPropertyName("webhook_event")]
        public object WebhookEvent { get; set; }
    }
}