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
});
