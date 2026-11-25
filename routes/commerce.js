const express = require('express');
const mongoose = require('mongoose');

const { Order, Cart, User } = require('../models');
const { requireAuth, requireAdmin, requireOwnerOrAdmin } = require('../middleware/auth');
const { orderLimiter, paymentLimiter, writeLimiter } = require('../middleware/rateLimiter');
const {
    handleValidation,
    paginationValidation,
    orderCreateValidation,
    orderStatusValidation,
    orderIdParamValidation,
    cartAddValidation,
    cartUpdateValidation,
    paymentValidation,
    voucherValidation,
} = require('../middleware/validators');

const router = express.Router();

// ---------------------------------------------------------------------------
// Cart - always scoped to the authenticated user
// ---------------------------------------------------------------------------

/** GET /cart */
router.get('/cart', requireAuth, async (req, res) => {
    try {
        const cart = await Cart.findOne({ email: req.user.email });
        return res.json(cart ? cart.items : []);
    } catch (err) {
        console.error('Error fetching cart:', err);
        return res.status(500).json({ error: 'Error fetching cart' });
    }
});

/** POST /cart - add (or increment) an item. */
router.post('/cart', requireAuth, writeLimiter, cartAddValidation, handleValidation, async (req, res) => {
    const { productId, medicineName, price, image_url, quantity = 1 } = req.body;
    try {
        let cart = await Cart.findOne({ email: req.user.email });
        if (!cart) {
            cart = new Cart({ email: req.user.email, items: [] });
        }
        const existingItem = cart.items.find((item) => item.productId === productId);
        if (existingItem) {
            existingItem.quantity += quantity;
        } else {
            cart.items.push({ productId, medicineName, price, image_url, quantity });
        }
        await cart.save();
        return res.json(cart.items);
    } catch (err) {
        console.error('Error adding to cart:', err);
        return res.status(500).json({ error: 'Error adding to cart' });
    }
});

/** PUT /cart - replace the whole cart. */
router.put('/cart', requireAuth, writeLimiter, cartUpdateValidation, handleValidation, async (req, res) => {
    const { items } = req.body;
    try {
        let cart = await Cart.findOne({ email: req.user.email });
        if (!cart) {
            cart = new Cart({ email: req.user.email, items: [] });
        }
        cart.items = items.map((item) => ({
            productId: item.productId,
            medicineName: item.medicineName,
            price: item.price,
            image_url: item.image_url,
            quantity: item.quantity,
        }));
        await cart.save();
        return res.json(cart.items);
    } catch (err) {
        console.error('Error updating cart:', err);
        return res.status(500).json({ error: 'Error updating cart' });
    }
});

/** DELETE /cart - empty the cart. */
router.delete('/cart', requireAuth, writeLimiter, async (req, res) => {
    try {
        await Cart.deleteOne({ email: req.user.email });
        return res.json({ message: 'Cart cleared' });
    } catch (err) {
        console.error('Error clearing cart:', err);
        return res.status(500).json({ error: 'Error clearing cart' });
    }
});


// ---------------------------------------------------------------------------
// Orders
// ---------------------------------------------------------------------------

/**
 * POST /orders - place an order.
 * The order is always attributed to the authenticated user and always starts
 * in the 'Pending' state - a client can never mark its own order as Paid.
 */
router.post('/orders', requireAuth, orderLimiter, orderCreateValidation, handleValidation, async (req, res) => {
    const { email, name, phoneNumber, address, items, total_price } = req.body;
    try {
        if (email !== req.user.email && req.user.role !== 'Admin') {
            return res.status(403).json({ error: 'Unauthorized to place an order for this email' });
        }

        const order = {
            email: req.user.email,
            name,
            phoneNumber,
            address,
            items,
            total_price: Number(total_price),
            status: 'Pending',
            order_date: new Date(),
        };
        const result = await Order.create(order);
        return res.json({ orderId: result._id });
    } catch (err) {
        console.error('Error placing order:', err);
        return res.status(500).json({ error: `Error placing order: ${err.message}` });
    }
});

/** GET /orders - every order. Admin only. */
router.get('/orders', requireAdmin, paginationValidation, handleValidation, async (req, res) => {
    try {
        const { page = 1, limit = 10 } = req.query;
        const skip = (Number(page) - 1) * Number(limit);
        const orders = await Order.find()
            .skip(skip)
            .limit(Number(limit))
            .lean();
        const total = await Order.countDocuments();
        return res.json({
            orders,
            total,
            pages: Math.ceil(total / Number(limit)),
        });
    } catch (err) {
        console.error('Error fetching orders:', err);
        return res.status(500).json({ error: 'Error fetching orders' });
    }
});

/**
 * GET /orders/:id - a single order by MongoDB id.
 * Matches `endpoints.orderById(id)` in the frontend contract.
 * Registered before /orders/:email so the ObjectId branch is evaluated first.
 */
router.get('/orders/:id', requireOwnerOrAdmin, async (req, res, next) => {
    const { id } = req.params;
    if (!mongoose.Types.ObjectId.isValid(id)) {
        // Not an ObjectId - let the /orders/:email route handle it.
        return next();
    }
    try {
        const order = await Order.findById(id).populate('items.productId', 'medicine_name price');
        if (!order) {
            return res.status(404).json({ error: 'Order not found' });
        }
        if (!req.isAdmin && order.email !== req.user.email) {
            return res.status(403).json({ error: 'Unauthorized to access this order' });
        }
        return res.json({
            _id: order._id,
            email: order.email,
            name: order.name,
            phoneNumber: order.phoneNumber,
            status: order.status,
            address: order.address,
            items: order.items,
            total_price: order.total_price,
        });
    } catch (err) {
        console.error('Error fetching order:', err);
        return res.status(500).json({ error: 'Error fetching order' });
    }
});


/** PUT /orders/:id - update the order status. Admin only. */
router.put('/orders/:id', requireAdmin, orderLimiter, orderStatusValidation, handleValidation, async (req, res) => {
    const { status } = req.body;
    try {
        const order = await Order.findById(req.params.id);
        if (!order) {
            return res.status(404).json({ error: 'Order not found' });
        }
        if (order.status === 'Paid') {
            return res.status(400).json({ error: 'Cannot update a Paid order' });
        }
        const result = await Order.updateOne(
            { _id: req.params.id },
            { $set: { status } }
        );
        if (result.modifiedCount === 0) {
            return res.status(400).json({ error: 'Order not found or status unchanged' });
        }
        console.log(`Updated order ID: ${req.params.id} to status: ${status}`);
        return res.json({ modifiedCount: result.modifiedCount });
    } catch (err) {
        console.error('Error updating order:', err);
        return res.status(500).json({ error: 'Error updating order' });
    }
});

/** DELETE /orders/:id - cancel an order. Owner or admin only. */
router.delete('/orders/:id', requireOwnerOrAdmin, writeLimiter, orderIdParamValidation, handleValidation, async (req, res) => {
    const { id } = req.params;
    try {
        const order = await Order.findOne({ _id: new mongoose.Types.ObjectId(id), email: req.user.email });
        if (!order) {
            // Admins may cancel any order.
            const adminOrder = req.isAdmin ? await Order.findById(id) : null;
            if (!adminOrder) {
                return res.status(404).json({ error: 'Order not found' });
            }
            if (adminOrder.status === 'Paid' || adminOrder.status === 'Shipped') {
                return res.status(400).json({ error: `Cannot cancel a ${adminOrder.status} order` });
            }
            await Order.deleteOne({ _id: adminOrder._id });
            return res.json({ message: 'Order cancelled successfully' });
        }
        if (order.status === 'Paid' || order.status === 'Shipped') {
            return res.status(400).json({ error: `Cannot cancel a ${order.status} order` });
        }
        await Order.deleteOne({ _id: order._id });
        return res.json({ message: 'Order cancelled successfully' });
    } catch (err) {
        console.error('Error cancelling order:', err);
        return res.status(500).json({ error: `Error cancelling order: ${err.message}` });
    }
});

/**
 * GET /order/:id - legacy singular alias of GET /orders/:id.
 * Kept so older frontend builds keep working; protection is identical.
 */
router.get('/order/:id', requireOwnerOrAdmin, orderIdParamValidation, handleValidation, async (req, res) => {
    try {
        const order = await Order.findById(req.params.id).populate('items.productId', 'medicine_name price');
        if (!order) {
            return res.status(404).json({ error: 'Order not found' });
        }
        if (!req.isAdmin && order.email !== req.user.email) {
            return res.status(403).json({ error: 'Unauthorized to access this order' });
        }
        return res.json({
            _id: order._id,
            email: order.email,
            name: order.name,
            phoneNumber: order.phoneNumber,
            status: order.status,
            address: order.address,
            items: order.items,
            total_price: order.total_price,
        });
    } catch (err) {
        console.error('Error fetching order:', err);
        return res.status(500).json({ error: 'Error fetching order' });
    }
});

/** GET /orders/:email - the orders belonging to a user. Owner or admin only. */

// ---------------------------------------------------------------------------
// Payments
// ---------------------------------------------------------------------------

/**
 * POST /payments - record a payment attempt against an order.
 * The caller must be the owner of the order (or an administrator).
 */
router.post('/payments', requireAuth, paymentLimiter, paymentValidation, handleValidation, async (req, res) => {
    const { orderId, email, paymentMethod, amount } = req.body;
    try {
        const order = await Order.findById(orderId);
        if (!order) {
            return res.status(404).json({ error: 'Order not found' });
        }
        if (order.email !== email) {
            return res.status(403).json({ error: 'Unauthorized: Email does not match order' });
        }
        if (email !== req.user.email && req.user.role !== 'Admin') {
            return res.status(403).json({ error: 'Unauthorized to pay for this order' });
        }
        if (order.status === 'Paid') {
            return res.status(400).json({ error: 'Order already paid' });
        }
        if (parseFloat(amount).toFixed(2) !== parseFloat(order.total_price).toFixed(2)) {
            return res.status(400).json({ error: 'Amount does not match order total' });
        }
        console.log(`Processed payment for order ID: ${orderId}, email: ${email}, method: ${paymentMethod}, amount: ${amount}`);
        return res.json({ success: true, orderId, amount });
    } catch (err) {
        console.error('Error processing payment:', err);
        return res.status(500).json({ error: 'Error processing payment' });
    }
});

// ---------------------------------------------------------------------------
// Vouchers
// ---------------------------------------------------------------------------

/** POST /vouchers/apply */
router.post('/vouchers/apply', requireAuth, writeLimiter, voucherValidation, handleValidation, async (req, res) => {
    const { code } = req.body;
    try {
        // Mock voucher logic
        const validVouchers = {
            rimonsir: 0.1,
            project_x: 0.2,
        };
        if (!validVouchers[code]) {
            return res.status(400).json({ error: 'Invalid voucher code' });
        }
        return res.json({ discount: validVouchers[code] });
    } catch (err) {
        console.error('Error applying voucher:', err);
        return res.status(500).json({ error: 'Error applying voucher' });
    }
});

// ---------------------------------------------------------------------------
// Admin analytics
// ---------------------------------------------------------------------------

/** GET /stats/revenue - admin only. */
router.get('/stats/revenue', requireAdmin, async (req, res) => {
    try {
        const result = await Order.aggregate([
            { $match: { status: 'Paid' } },
            { $group: { _id: null, revenue: { $sum: '$total_price' } } },
        ]);
        const revenue = result.length > 0 ? result[0].revenue : 0;
        return res.json({ revenue });
    } catch (err) {
        console.error('Error fetching revenue:', err);
        return res.status(500).json({ error: 'Error fetching revenue' });
    }
});

/** GET /stats/total-sales - admin only. */
router.get('/stats/total-sales', requireAdmin, async (req, res) => {
    try {
        const result = await Order.aggregate([
            { $match: { status: 'Paid' } },
            { $unwind: '$items' },
            { $group: { _id: null, totalSales: { $sum: '$items.quantity' } } },
        ]);
        const totalSales = result.length > 0 ? result[0].totalSales : 0;
        return res.json({ totalSales });
    } catch (err) {
        console.error('Error fetching total sales:', err);
        return res.status(500).json({ error: 'Error fetching total sales' });
    }
});

/** GET /stats/top-products - admin only. */
router.get('/stats/top-products', requireAdmin, async (req, res) => {
    try {
        const topProducts = await Order.aggregate([
            { $match: { status: 'Paid' } },
            { $unwind: '$items' },
            {
                $group: {
                    _id: '$items.medicineName',
                    totalQuantity: { $sum: '$items.quantity' },
                    price: { $first: '$items.price' },
                },
            },
            { $sort: { totalQuantity: -1 } },
            { $limit: 5 },
            {
                $project: {
                    _id: 0,
                    medicineName: '$_id',
                    totalQuantity: 1,
                    price: 1,
                },
            },
        ]);
        return res.json(topProducts);
    } catch (err) {
        console.error('Error fetching top products:', err);
        return res.status(500).json({ error: 'Error fetching top products' });
    }
});

/** GET /stats/total-users - admin only. */
router.get('/stats/total-users', requireAdmin, async (req, res) => {
    try {
        const totalUsers = await User.countDocuments();
        return res.json({ totalUsers });
    } catch (err) {
        console.error('Error fetching total users:', err);
        return res.status(500).json({ error: 'Error fetching total users' });
    }
});

module.exports = router;

router.get('/orders/:email', requireOwnerOrAdmin, async (req, res) => {
    const { email } = req.params;
    try {
        if (!req.isAdmin && email !== req.user.email) {
            return res.status(403).json({ error: 'Unauthorized to access orders for this email' });
        }
        const orders = await Order.find({ email });
        return res.json(orders);
    } catch (err) {
        console.error('Error fetching orders:', err);
        return res.status(500).json({ error: `Error fetching orders: ${err.message}` });
    }
});
