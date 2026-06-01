package main

type URL struct {
	URL string `json:"url"`
}

type AuthVerdict struct {
	SPF   string `json:"spf"`
	DKIM  string `json:"dkim"`
	DMARC string `json:"dmarc"`
}

type Summary struct {
	From              string `json:"from"`
	Subject           string `json:"subject"`
	Attachments_count int    `json:"attachments_count"`
	URLS_count        int    `json:"urls_count"`
}

type Attachment struct {
	Filename    string      `json:"filename"`
	ContentType string      `json:"content_type"`
	Hash        string      `json:"hash"`
	Results     interface{} `json:"results"`
}

type Attachments []Attachment
