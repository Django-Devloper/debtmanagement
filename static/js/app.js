document.addEventListener('DOMContentLoaded', () => {
  const payoffForm = document.getElementById('payoff-calculator');
  const payoffResult = document.getElementById('payoff-result');

  if (payoffForm && payoffResult) {
    payoffForm.addEventListener('submit', (event) => {
      event.preventDefault();
      const data = new FormData(payoffForm);
      const balance = parseFloat(data.get('balance')) || 0;
      const rate = parseFloat(data.get('rate')) || 0;
      const payment = parseFloat(data.get('payment')) || 0;

      if (balance <= 0 || payment <= 0) {
        payoffResult.textContent = 'Enter balance and payment to calculate.';
        return;
      }

      const monthlyRate = rate / 100 / 12;
      let months;

      if (monthlyRate === 0) {
        months = balance / payment;
      } else {
        const numerator = Math.log(payment) - Math.log(payment - monthlyRate * balance);
        const denominator = Math.log(1 + monthlyRate);
        months = numerator / denominator;
      }

      if (!isFinite(months) || months <= 0) {
        payoffResult.textContent = 'Payment is too low to cover interest.';
        return;
      }

      payoffResult.textContent = `You will be debt-free in ${Math.ceil(months)} months.`;
    });
  }

  const stepForm = document.getElementById('step-form');
  const stepNumber = document.getElementById('step-number');
  const stepSummary = document.querySelector('#step-summary ul');

  if (stepForm && stepNumber && stepSummary) {
    let stepCount = 1;

    stepForm.addEventListener('submit', async (event) => {
      event.preventDefault();
      const payload = new FormData(stepForm);
      const response = await fetch('/debts', {
        method: 'POST',
        body: payload,
      });

      if (response.redirected) {
        // stay on page but refresh summary via API
        fetch('/api/debts')
          .then((res) => res.json())
          .then((data) => {
            stepSummary.innerHTML = data.debts
              .map((debt) => `<li>${debt.creditor} – ₹${debt.outstanding_amount.toFixed(2)}</li>`)
              .join('');
          });
      }

      stepCount += 1;
      stepNumber.textContent = stepCount;
      stepForm.reset();
    });

    document.getElementById('save-quit').addEventListener('click', () => {
      window.location.href = '/';
    });
  }

  const chartDataNode = document.getElementById('chart-data');
  let chartPayload = null;
  if (chartDataNode) {
    try {
      chartPayload = JSON.parse(chartDataNode.dataset.chart || '{}');
    } catch (err) {
      console.warn('Unable to parse chart bootstrap data', err);
    }
  }

  const ChartLib = window.Chart;
  if (ChartLib && chartPayload) {
    const snowSeries = (chartPayload.timeline && chartPayload.timeline.snowball) || [];
    const avalancheSeries = (chartPayload.timeline && chartPayload.timeline.avalanche) || [];
    const labels = Array.from(
      new Set([
        ...snowSeries.map((point) => point.month),
        ...avalancheSeries.map((point) => point.month),
      ])
    ).sort((a, b) => a - b);

    function seriesValues(series, axisLabels) {
      if (!series.length) {
        return axisLabels.map(() => 0);
      }
      let idx = 0;
      let current = series[0].balance;
      return axisLabels.map((label) => {
        while (idx + 1 < series.length && series[idx + 1].month <= label) {
          idx += 1;
          current = series[idx].balance;
        }
        return current;
      });
    }

    const timelineCanvas = document.getElementById('timeline-chart');
    if (timelineCanvas && labels.length) {
      new ChartLib(timelineCanvas.getContext('2d'), {
    new ChartLib(timelineCanvas.getContext('2d'), {
      type: 'line',
      data: {
        labels,
        datasets: [
          {
            label: 'Snowball balance',
            data: seriesValues(snowSeries, labels),
            borderColor: '#0ea5e9',
            backgroundColor: 'rgba(14, 165, 233, 0.15)',
            tension: 0.35,
            fill: true,
          },
          {
            label: 'Avalanche balance',
            data: seriesValues(avalancheSeries, labels),
            borderColor: '#f97316',
            backgroundColor: 'rgba(249, 115, 22, 0.15)',
            tension: 0.35,
            fill: true,
          },
        ],
      },
      options: {
        responsive: true,
        plugins: {
          legend: {
            position: 'bottom',
          },
        },
        interaction: {
          mode: 'index',
          intersect: false,
        },
        scales: {
          y: {
            beginAtZero: true,
            ticks: {
              callback: (value) => `₹${Number(value).toLocaleString()}`,
            },
          },
          x: {
            title: {
              display: true,
              text: 'Months',
            },
          },
        },
      },
    });
    }

    const barCanvas = document.getElementById('strategy-bars');
    if (barCanvas && chartPayload.months) {
      new ChartLib(barCanvas.getContext('2d'), {
    new ChartLib(barCanvas.getContext('2d'), {
      type: 'bar',
      data: {
        labels: ['Snowball', 'Avalanche'],
        datasets: [
          {
            label: 'Months to debt-free',
            backgroundColor: ['#0ea5e9', '#f97316'],
            data: [chartPayload.months.snowball || 0, chartPayload.months.avalanche || 0],
            borderRadius: 12,
          },
        ],
      },
      options: {
        responsive: true,
        plugins: {
          legend: { display: false },
        },
        scales: {
          y: {
            beginAtZero: true,
            ticks: {
              stepSize: 6,
            },
          },
        },
      },
    });
    }

    if (Array.isArray(chartPayload.debtProgress)) {
      chartPayload.debtProgress.forEach((item) => {
        const canvas = document.getElementById(`debt-chart-${item.id}`);
        if (!canvas) return;
        const paid = Number(item.paid) || 0;
        const remaining = Number(item.remaining) || 0;
        if (paid === 0 && remaining === 0) {
          return;
        }
        new ChartLib(canvas.getContext('2d'), {
          type: 'doughnut',
          data: {
            labels: ['Paid', 'Remaining'],
            datasets: [
              {
                data: [paid, remaining],
                backgroundColor: ['#22c55e', '#f97316'],
                borderWidth: 0,
              },
            ],
          },
          options: {
            plugins: {
              legend: { display: false },
              tooltip: {
                callbacks: {
                  label(context) {
                    return `${context.label}: ₹${Number(context.parsed).toLocaleString()}`;
                  },
                },
              },
            },
            cutout: '65%',
          },
        });
      });
    }
  }
});
