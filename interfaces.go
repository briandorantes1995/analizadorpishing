package main

type URL struct {
	URL string `json:"url"`
}

type AuthVerdict struct {
	SPF   string `json:"spf"`
	DKIM  string `json:"dkim"`
	DMARC string `json:"dmarc"`
	IP    *IPInfo
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

type IPInfo struct {
	Status  string `json:"status"`
	Country string `json:"country"`
	City    string `json:"city"`
	Query   string `json:"query"`
}

type Attachments []Attachment

type URLScanResponse struct {
	Uuid       string `json:"uuid"`
	Visibility string `json:"visibility"`
	Url        string `json:"url"`
	Country    string `json:"country"`
}

type URLVerdict struct {
	Overall   interface{} `json:"overall"`
	Urlscan   interface{} `json:"urlscan"`
	Engines   interface{} `json:"engines"`
	Community interface{} `json:"community"`
}

type URLScanResult struct {
	URLVERDICT URLVerdict `json:"verdicts"`
}

type URLScanResults []URLScanResult

type ApiResponse struct {
	Message        string      `json:"message"`
	Authentication AuthVerdict `json:"authentication"`
	Summary        Summary     `json:"summary"`
	Attachments    Attachments `json:"attachments"`
}
