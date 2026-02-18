use maud::{Markup, PreEscaped, html};

// Function to render the Mint V2 module UI section
pub async fn render(mint: &fedimint_mintv2_server::Mint) -> Markup {
    let distribution = mint.note_distribution_ui().await;

    let labels: Vec<String> = distribution.keys().map(|d| format!("2^{}", d.0)).collect();
    let counts: Vec<u64> = distribution.values().copied().collect();

    html! {
        div class="card h-100" {
            div class="card-header dashboard-header" { "Mint V2" }
            div class="card-body" {
                @if distribution.is_empty() {
                    p class="text-muted mb-0" { "No notes have been issued yet." }
                } @else {
                    canvas id="mintv2-chart" {}
                    script src="/assets/chart.umd.min.js" {}
                    (PreEscaped(format!(
                        r#"<script>
                        document.addEventListener('DOMContentLoaded', function() {{
                            new Chart(document.getElementById('mintv2-chart'), {{
                                type: 'bar',
                                data: {{
                                    labels: {labels},
                                    datasets: [{{
                                        label: 'Outstanding Notes',
                                        data: {counts:?},
                                        borderWidth: 1
                                    }}]
                                }},
                                options: {{
                                    responsive: true,
                                    plugins: {{
                                        legend: {{ display: false }},
                                        tooltip: {{ enabled: false }}
                                    }},
                                    scales: {{
                                        x: {{
                                            title: {{
                                                display: true,
                                                text: 'Denomination'
                                            }}
                                        }},
                                        y: {{
                                            beginAtZero: true,
                                            title: {{
                                                display: true,
                                                text: 'Outstanding Note Count'
                                            }}
                                        }}
                                    }}
                                }}
                            }});
                        }});
                        </script>"#,
                        labels = serde_json::to_string(&labels)
                            .expect("Failed to serialize labels"),
                    )))
                }
            }
        }
    }
}
