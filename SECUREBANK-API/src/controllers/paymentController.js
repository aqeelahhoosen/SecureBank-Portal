const Payment = require('../models/Payment');

exports.createPayment = async (req, res) => {
  try {
    const { amount, currency, payeeAccountNumber, swiftCode, beneficiaryName } = req.body;
    const userId = req.user._id;

    // Create payment
    const payment = new Payment({
      amount,
      currency: currency.toUpperCase(),
      payeeAccountNumber,
      swiftCode: swiftCode.toUpperCase(),
      beneficiaryName,
      userId
    });

    await payment.save();

    res.status(201).json({
      success: true,
      message: 'Payment created successfully',
      data: {
        payment: {
          id: payment._id,
          amount: payment.amount,
          currency: payment.currency,
          payeeAccountNumber: payment.payeeAccountNumber,
          swiftCode: payment.swiftCode,
          beneficiaryName: payment.beneficiaryName,
          status: payment.status,
          createdAt: payment.createdAt
        }
      }
    });

  } catch (error) {
    console.error('Create payment error:', error);
    res.status(500).json({
      success: false,
      message: 'Error creating payment'
    });
  }
};

exports.getUserPayments = async (req, res) => {
  try {
    const userId = req.user._id;
    const payments = await Payment.find({ userId }).sort({ createdAt: -1 });

    res.json({
      success: true,
      data: {
        payments
      }
    });

  } catch (error) {
    console.error('Get payments error:', error);
    res.status(500).json({
      success: false,
      message: 'Error retrieving payments'
    });
  }
};

exports.getPendingPayments = async (req, res) => {
  try {
    const payments = await Payment.find({ status: 'Pending' })
      .populate('userId', 'fullName accountNumber')
      .sort({ createdAt: -1 });

    const formattedPayments = payments.map(payment => ({
      id: payment._id,
      amount: payment.amount,
      currency: payment.currency,
      payeeAccountNumber: payment.payeeAccountNumber,
      swiftCode: payment.swiftCode,
      beneficiaryName: payment.beneficiaryName,
      createdAt: payment.createdAt,
      userFullName: payment.userId.fullName,
      userAccountNumber: payment.userId.accountNumber
    }));

    res.json({
      success: true,
      data: {
        payments: formattedPayments
      }
    });

  } catch (error) {
    console.error('Get pending payments error:', error);
    res.status(500).json({
      success: false,
      message: 'Error retrieving pending payments'
    });
  }
};

exports.verifyPayment = async (req, res) => {
  try {
    const { id } = req.params;

    const payment = await Payment.findByIdAndUpdate(
      id,
      { status: 'Verified' },
      { new: true }
    );

    if (!payment) {
      return res.status(404).json({
        success: false,
        message: 'Payment not found'
      });
    }

    res.json({
      success: true,
      message: 'Payment verified successfully'
    });

  } catch (error) {
    console.error('Verify payment error:', error);
    res.status(500).json({
      success: false,
      message: 'Error verifying payment'
    });
  }
};