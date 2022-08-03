using Azure;
using Azure.Data.Tables;
using System;

namespace isds_oauth2_proxy.Model
{
    internal class IsdsRedirectState : ITableEntity
    {
        public string PartitionKey { get; set; }
        public string RowKey { get; set; }
        public DateTimeOffset? Timestamp { get; set; }
        public ETag ETag { get; set; }
        public string State { get; set; }
    }
}
