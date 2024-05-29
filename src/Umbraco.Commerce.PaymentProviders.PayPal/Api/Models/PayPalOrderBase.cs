using System.Text.Json.Serialization;

namespace Umbraco.Commerce.PaymentProviders.PayPal.Api.Models
{
    public class PayPalOrderBase<TPaymentUnit> : PayPalOrderMinimal
        where TPaymentUnit : PayPalPurchaseUnitBase
    {
        [JsonPropertyName("intent")]
        public string Intent { get; set; }

        [JsonPropertyName("purchase_units")]
        public TPaymentUnit[] PurchaseUnits { get; set; }

        [JsonPropertyName("application_context")]
        public PayPalOrderApplicationContext AplicationContext { get; set; }
    }
}