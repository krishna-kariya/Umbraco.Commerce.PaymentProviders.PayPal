using System.Text.Json.Serialization;

namespace Umbraco.Commerce.PaymentProviders.PayPal.Api.Models
{
    // https://developer.paypal.com/docs/api/orders/v2/#definition-order_application_context

    public class PayPalOrderApplicationContext
    {
        [JsonPropertyName("brand_name")]
        public string BrandName { get; set; }

        [JsonPropertyName("locale")]
        public string Locale { get; set; }

        [JsonPropertyName("landing_page")]
        public string LandingPage { get; set; }

        [JsonPropertyName("shipping_preference")]
        public string ShippingPreference { get; set; }

        [JsonPropertyName("user_action")]
        public string UserAction { get; set; }

        [JsonPropertyName("return_url")]
        public string ReturnUrl { get; set; }

        [JsonPropertyName("cancel_url")]
        public string CancelUrl { get; set; }

        public PayPalOrderApplicationContext()
        {
            LandingPage = "NO_PREFERENCE";
            ShippingPreference = "GET_FROM_FILE";
            UserAction = "CONTINUE";
        }
    }
}