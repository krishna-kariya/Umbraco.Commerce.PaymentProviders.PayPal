using System.Text.Json;
using System.Text.Json.Serialization;

namespace Umbraco.Commerce.PaymentProviders.PayPal.Api.Models
{
    public class PayPalWebhookEvent
    {
        public static class ResourceTypes
        {
            public static class Payment
            {
                public const string CAPTURE = "capture";
                public const string AUTHORIZATION = "authorization";
                public const string REFUND = "refund";
            }
            public static class Order
            {
                public const string CHECKOUT_ORDER = "checkout-order";
            }
        }

        [JsonPropertyName("id")]
        public string Id { get; set; }

        [JsonPropertyName("event_type")]
        public string EventType { get; set; }

        [JsonPropertyName("event_version")]
        public string EventVersion { get; set; }

        [JsonPropertyName("resource_type")]
        public string ResourceType { get; set; }

        [JsonPropertyName("resource_version")]
        public string ResourceVersion { get; set; }

        [JsonPropertyName("summary")]
        public string Summary { get; set; }

        [JsonPropertyName("resource")]
        public JsonNode Resource { get; set; }

        [JsonPropertyName("create_time")]
        public string CreateTime { get; set; }

        [JsonPropertyName("links")]
        public PayPalHateoasLink[] Links { get; set; }
    }
}