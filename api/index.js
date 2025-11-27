// /api/index.js (Final and Secure Version)

/**
 * SHIB Ads WebApp Backend API
 * Handles all POST requests from the Telegram Mini App frontend.
 * Uses the Supabase REST API for persistence.
 */
const crypto = require('crypto');

// Load environment variables for Supabase connection
const SUPABASE_URL = process.env.NEXT_PUBLIC_SUPABASE_URL;
const SUPABASE_ANON_KEY = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY;
// ⚠️ BOT_TOKEN must be set in Vercel environment variables
const BOT_TOKEN = process.env.BOT_TOKEN;

// ------------------------------------------------------------------
// Fully secured and defined server-side constants
// ------------------------------------------------------------------
const REWARD_PER_AD = 3;
const REFERRAL_COMMISSION_RATE = 0.05;
const DAILY_MAX_ADS = 100; // Max ads limit
const DAILY_MAX_SPINS = 15; // Max spins limit
const MIN_TIME_BETWEEN_ACTIONS_MS = 3000; // 3 seconds minimum time between watchAd/spin requests
const ACTION_ID_EXPIRY_MS = 60000; // 60 seconds for Action ID to be valid
const SPIN_SECTORS = [5, 10, 15, 20, 5];

/**
 * Helper function to randomly select a prize from the defined sectors and return its index.
 */
function calculateRandomSpinPrize() {
    const randomIndex = Math.floor(Math.random() * SPIN_SECTORS.length);
    const prize = SPIN_SECTORS[randomIndex];
    return { actual_prize: prize, prize_index: randomIndex };
}


// --- Supabase Setup ---
const createSupabaseClient = (url, key) => {
    // A simplified client for REST API calls
    const headers = {
        'Content-Type': 'application/json',
        'apikey': key,
        'Authorization': `Bearer ${key}`
    };

    return {
        from: (tableName) => ({
            select: async (columns) => {
                const urlObj = new URL(`${url}/rest/v1/${tableName}`);
                urlObj.searchParams.set('select', columns);
                
                return {
                    eq: async (column, value) => {
                        urlObj.searchParams.set(column, `eq.${value}`);
                        const response = await fetch(urlObj.toString(), { method: 'GET', headers });
                        const data = await response.json();
                        return { data, error: response.ok ? null : data };
                    },
                    limit: async (count) => {
                         urlObj.searchParams.set('limit', count);
                         const response = await fetch(urlObj.toString(), { method: 'GET', headers });
                         const data = await response.json();
                         return { data, error: response.ok ? null : data };
                    },
                    order: async (column, ascending = true) => {
                         urlObj.searchParams.set('order', column + (ascending ? '.asc' : '.desc'));
                         const response = await fetch(urlObj.toString(), { method: 'GET', headers });
                         const data = await response.json();
                         return { data, error: response.ok ? null : data };
                    },
                    single: async () => {
                        urlObj.searchParams.set('limit', 1);
                        urlObj.searchParams.set('single', true);
                        const response = await fetch(urlObj.toString(), { method: 'GET', headers });
                        const data = await response.json();
                        if (response.status === 406) return { data: null, error: null }; // Supabase returns 406 for single query with no results
                        return { data, error: response.ok ? null : data };
                    }
                };
            },
            insert: async (row) => {
                const urlObj = new URL(`${url}/rest/v1/${tableName}`);
                const response = await fetch(urlObj.toString(), {
                    method: 'POST',
                    headers: { ...headers, 'Prefer': 'return=representation' },
                    body: JSON.stringify(row)
                });
                const data = await response.json();
                return { data, error: response.ok ? null : data };
            },
            update: async (updates) => {
                const urlObj = new URL(`${url}/rest/v1/${tableName}`);
                return {
                    eq: async (column, value) => {
                        urlObj.searchParams.set(column, `eq.${value}`);
                        const response = await fetch(urlObj.toString(), {
                            method: 'PATCH',
                            headers: { ...headers, 'Prefer': 'return=representation' },
                            body: JSON.stringify(updates)
                        });
                        const data = await response.json();
                        return { data, error: response.ok ? null : data };
                    }
                };
            },
            rpc: async (functionName, params) => {
                const urlObj = new URL(`${url}/rest/v1/rpc/${functionName}`);
                const response = await fetch(urlObj.toString(), {
                    method: 'POST',
                    headers: headers,
                    body: JSON.stringify(params)
                });
                const data = await response.json();
                return { data, error: response.ok ? null : data };
            }
        })
    };
};

const supabase = createSupabaseClient(SUPABASE_URL, SUPABASE_ANON_KEY);
// --- End Supabase Setup ---


// --- Helper Functions ---
function sendResponse(res, data, status = 200) {
    res.writeHead(status, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(data));
}

function sendError(res, message, status = 500) {
    console.error('API Error:', message);
    sendResponse(res, { ok: false, error: message }, status);
}

// Security function to validate Telegram InitData
function validateInitData(initData) {
    if (!initData || !BOT_TOKEN) return false;

    const items = initData.split('&').filter(i => i.split('=')[0] !== 'hash');
    items.sort();
    const dataCheckString = items.join('\n');

    const secret = crypto.createHmac('sha256', 'WebAppData').update(BOT_TOKEN).digest();
    const hash = crypto.createHmac('sha256', secret).update(dataCheckString).digest('hex');

    const receivedHash = initData.split('hash=')[1];

    // Check if the hash matches and if the data is recent (e.g., within 60 minutes)
    const authDateMatch = initData.match(/auth_date=(\d+)/);
    const authDate = authDateMatch ? parseInt(authDateMatch[1]) * 1000 : 0;
    const isRecent = (Date.now() - authDate) < 3600000; // 1 hour

    return hash === receivedHash && isRecent;
}
// --- End Helper Functions ---


// ------------------------------------------------------------------
// Handlers (API Logic)
// ------------------------------------------------------------------

/**
 * Generates a unique, expiring action ID for security.
 */
async function handleGenerateActionId(req, res, body) {
    const { user_id, action_type } = body;
    const token = crypto.randomBytes(16).toString('hex');
    const expires_at = new Date(Date.now() + ACTION_ID_EXPIRY_MS);
    
    try {
        const { error } = await supabase.from('action_tokens').insert({ 
            user_id, 
            action_type, 
            token, 
            expires_at 
        });

        if (error) {
            return sendError(res, `Failed to generate token: ${error.message}`, 500);
        }

        sendResponse(res, { ok: true, data: { action_id: token } });
    } catch (e) {
        sendError(res, 'Server error during token generation.', 500);
    }
}

/**
 * Validates and consumes the action token.
 * Returns true if valid and consumed, false otherwise.
 */
async function consumeActionToken(user_id, action_id, action_type) {
    try {
        // 1. Check for token existence and validity (including not consumed and not expired)
        const { data: tokenData, error: fetchError } = await supabase
            .from('action_tokens')
            .select('id, expires_at')
            .eq('user_id', user_id)
            .eq('token', action_id)
            .eq('action_type', action_type)
            .eq('consumed', false)
            .single();

        if (fetchError || !tokenData) {
            console.warn(`Token validation failed for user ${user_id}, type ${action_type}`);
            return false;
        }

        // Check expiry
        if (new Date(tokenData.expires_at) < new Date()) {
            console.warn(`Token expired for user ${user_id}`);
            return false;
        }

        // 2. Consume the token (set consumed = true)
        const { error: updateError } = await supabase
            .from('action_tokens')
            .update({ consumed: true })
            .eq('id', tokenData.id);

        if (updateError) {
            // Log warning but treat as consumed for security (prevent reuse attempt)
            console.warn(`Failed to mark token as consumed: ${updateError.message}`);
        }
        
        return true;

    } catch (e) {
        console.error('Token consumption exception:', e.message);
        return false;
    }
}


/**
 * Handles user registration and referrer logging.
 */
async function handleRegister(req, res, body) {
    const { user_id, ref_by } = body;
    
    try {
        const { data: existingUser } = await supabase
            .from('users')
            .select('id')
            .eq('id', user_id)
            .single();

        if (existingUser) {
            return sendResponse(res, { ok: true, message: 'User already registered.' });
        }
        
        // Check if ref_by is a valid, existing user
        let final_ref_by = null;
        if (ref_by) {
             const { data: referrer } = await supabase
                .from('users')
                .select('id')
                .eq('id', ref_by)
                .single();
            if (referrer) {
                final_ref_by = ref_by;
            } else {
                console.warn(`Referrer ID ${ref_by} not found in database.`);
            }
        }

        const { error: insertError } = await supabase
            .from('users')
            .insert({ 
                id: user_id, 
                balance: 0, 
                ads_watched_today: 0, 
                spins_today: 0, 
                ref_by: final_ref_by 
            });

        if (insertError) {
            return sendError(res, `Failed to register user: ${insertError.message}`, 500);
        }
        
        // Log the referral count update (for the referrer)
        if (final_ref_by) {
            const { error: refError } = await supabase.from('referrals').insert({
                referrer_id: final_ref_by,
                referee_id: user_id
            });
            if (refError) console.error("Failed to log referral count:", refError.message);
        }

        sendResponse(res, { ok: true, message: 'User registered successfully.' });

    } catch (e) {
        sendError(res, `Server error during registration: ${e.message}`, 500);
    }
}


/**
 * Retrieves all user data needed for the frontend.
 */
async function handleGetUserData(req, res, body) {
    const { user_id } = body;

    try {
        // 1. Get main user data, including the referrer ID (ref_by)
        const { data: userData, error: userError } = await supabase
            .from('users')
            .select('balance, ads_watched_today, spins_today, is_banned, withdrawal_history, ref_by, last_activity') // ⬅️ ADDED ref_by
            .eq('id', user_id)
            .single();

        if (userError || !userData) {
            return sendError(res, `User data not found: ${userError?.message || 'No data'}`, 404);
        }

        // Check ban status immediately
        if (userData.is_banned) {
            return sendError(res, 'User is banned.', 403);
        }
        
        // 2. Get referral count
        const { count: referralsCount, error: countError } = await supabase
            .from('referrals')
            .select('*', { count: 'exact', head: true })
            .eq('referrer_id', user_id);

        if (countError) {
            console.warn('Failed to fetch referral count:', countError.message);
        }
        
        // 3. Update last activity (if not banned)
        const { error: updateActivityError } = await supabase
            .from('users')
            .update({ last_activity: new Date().toISOString() })
            .eq('id', user_id);
            
        if (updateActivityError) {
             console.warn('Failed to update last_activity:', updateActivityError.message);
        }

        sendResponse(res, { 
            ok: true, 
            data: {
                balance: userData.balance,
                ads_watched_today: userData.ads_watched_today,
                spins_today: userData.spins_today,
                is_banned: userData.is_banned,
                withdrawal_history: userData.withdrawal_history,
                referrals_count: referralsCount || 0,
                ref_by: userData.ref_by // ⬅️ ADDED ref_by to the response
            }
        });

    } catch (e) {
        sendError(res, `Server error during data retrieval: ${e.message}`, 500);
    }
}


/**
 * Handles the watch ad reward process.
 */
async function handleWatchAd(req, res, body) {
    const { user_id, action_id } = body;
    const reward = REWARD_PER_AD;

    // 1. Validate and Consume Action Token
    if (!await consumeActionToken(user_id, action_id, 'watchAd')) {
        return sendError(res, 'Invalid or used Server Token.', 409);
    }

    try {
        // 2. Get user data for checks (limits and balance)
        const { data: userData, error: fetchError } = await supabase
            .from('users')
            .select('balance, ads_watched_today, is_banned, last_ad_time')
            .eq('id', user_id)
            .single();

        if (fetchError || !userData) {
            return sendError(res, `User not found or fetch error: ${fetchError?.message || 'No data'}`, 404);
        }
        if (userData.is_banned) {
            return sendError(res, 'User is banned.', 403);
        }

        // Check timing (anti-spam)
        if (userData.last_ad_time && (Date.now() - new Date(userData.last_ad_time).getTime()) < MIN_TIME_BETWEEN_ACTIONS_MS) {
             return sendError(res, `Rate limit exceeded. Try again in ${MIN_TIME_BETWEEN_ACTIONS_MS / 1000} seconds.`, 429);
        }
        
        // Check daily limit
        if (userData.ads_watched_today >= DAILY_MAX_ADS) {
            return sendError(res, 'Daily ad limit reached.', 403);
        }

        // 3. Perform the update (reward, increment count, update time)
        const newBalance = userData.balance + reward;
        const newCount = userData.ads_watched_today + 1;
        
        const { data: updatedData, error: updateError } = await supabase
            .from('users')
            .update({ 
                balance: newBalance, 
                ads_watched_today: newCount,
                last_ad_time: new Date().toISOString()
            })
            .eq('id', user_id);

        if (updateError) {
            return sendError(res, `Failed to update user balance: ${updateError.message}`, 500);
        }
        
        // 4. Send success response
        sendResponse(res, { 
            ok: true, 
            data: { 
                new_balance: newBalance, 
                new_ads_count: newCount, 
                actual_reward: reward 
            } 
        });

    } catch (e) {
        sendError(res, `Server error during ad reward process: ${e.message}`, 500);
    }
}


/**
 * Handles referral commission logging and distribution.
 * NOTE: This is called by the referee (the user who watched the ad)
 */
async function handleCommission(req, res, body) {
    // No initData check for commission, rely on the integrity of the watchAd/spin call
    const { referrer_id, referee_id } = body;
    
    // Safety check: Don't process commission if IDs are the same
    if (!referrer_id || referrer_id === referee_id) {
        return sendResponse(res, { ok: true, message: 'No valid referrer or self-referral, skipping commission.' });
    }
    
    const commissionAmount = REWARD_PER_AD * REFERRAL_COMMISSION_RATE;
    
    try {
        // 1. Get referrer's current balance
        const { data: referrerData, error: fetchError } = await supabase
            .from('users')
            .select('balance')
            .eq('id', referrer_id)
            .single();

        if (fetchError || !referrerData) {
            console.warn(`Referrer ${referrer_id} not found for commission.`);
            return sendResponse(res, { ok: true, message: 'Referrer not found, commission skipped.' });
        }

        // 2. Update referrer's balance
        const newBalance = referrerData.balance + commissionAmount;
        
        const { error: updateError } = await supabase
            .from('users')
            .update({ balance: newBalance })
            .eq('id', referrer_id);

        if (updateError) {
             console.error(`Failed to update referrer balance: ${updateError.message}`);
             // Continue to log the commission attempt, but return success to the front-end to prevent loops
        }
        
        // 3. Log the commission in the commissions table
        const { error: logError } = await supabase
            .from('commissions')
            .insert({
                referrer_id,
                referee_id,
                amount: commissionAmount,
                source_type: 'ad_view'
            });

        if (logError) {
            console.error(`Failed to log commission: ${logError.message}`);
        }

        sendResponse(res, { ok: true, data: { commission_amount: commissionAmount } });

    } catch (e) {
        sendError(res, `Server error during commission process: ${e.message}`, 500);
    }
}


/**
 * Handles the pre-spin security check and generates an Action ID.
 */
async function handlePreSpin(req, res, body) {
    const { user_id } = body;
    
    try {
        // 1. Get user data for limit check
        const { data: userData, error: fetchError } = await supabase
            .from('users')
            .select('spins_today, is_banned')
            .eq('id', user_id)
            .single();

        if (fetchError || !userData) {
            return sendError(res, `User not found or fetch error: ${fetchError?.message || 'No data'}`, 404);
        }
        if (userData.is_banned) {
            return sendError(res, 'User is banned.', 403);
        }
        
        // Check daily spin limit
        if (userData.spins_today >= DAILY_MAX_SPINS) {
            return sendError(res, 'Daily spin limit reached.', 403);
        }
        
        // 2. Generate and store Action ID (preSpin)
        await handleGenerateActionId(req, res, { user_id, action_type: 'spinResult' });
        // NOTE: handleGenerateActionId sends the final response
        
    } catch (e) {
        sendError(res, `Server error during pre-spin check: ${e.message}`, 500);
    }
}


/**
 * Handles the spin result process (consumes token, applies prize, increments count).
 */
async function handleSpinResult(req, res, body) {
    const { user_id, action_id } = body;
    const { actual_prize, prize_index } = calculateRandomSpinPrize(); // Server calculates the prize

    // 1. Validate and Consume Action Token (from preSpin)
    if (!await consumeActionToken(user_id, action_id, 'spinResult')) {
        return sendError(res, 'Invalid or used Server Token.', 409);
    }
    
    try {
        // 2. Get user data for final checks and balance update
        const { data: userData, error: fetchError } = await supabase
            .from('users')
            .select('balance, spins_today, is_banned, last_spin_time')
            .eq('id', user_id)
            .single();
            
        if (fetchError || !userData) {
            return sendError(res, `User not found or fetch error: ${fetchError?.message || 'No data'}`, 404);
        }
        if (userData.is_banned) {
            return sendError(res, 'User is banned.', 403);
        }
        
        // Check timing (anti-spam)
        if (userData.last_spin_time && (Date.now() - new Date(userData.last_spin_time).getTime()) < MIN_TIME_BETWEEN_ACTIONS_MS) {
             return sendError(res, `Rate limit exceeded. Try again in ${MIN_TIME_BETWEEN_ACTIONS_MS / 1000} seconds.`, 429);
        }

        // Check daily spin limit (double-check after token check)
        if (userData.spins_today >= DAILY_MAX_SPINS) {
            return sendError(res, 'Daily spin limit reached.', 403);
        }

        // 3. Perform the update (reward, increment count, update time)
        const newBalance = userData.balance + actual_prize;
        const newCount = userData.spins_today + 1;
        
        const { error: updateError } = await supabase
            .from('users')
            .update({ 
                balance: newBalance, 
                spins_today: newCount,
                last_spin_time: new Date().toISOString()
            })
            .eq('id', user_id);

        if (updateError) {
            return sendError(res, `Failed to update user balance: ${updateError.message}`, 500);
        }
        
        // 4. Send success response (includes the actual prize and its index)
        sendResponse(res, { 
            ok: true, 
            data: { 
                new_balance: newBalance, 
                new_spins_count: newCount, 
                actual_prize: actual_prize,
                prize_index: prize_index 
            } 
        });

    } catch (e) {
        sendError(res, `Server error during spin reward process: ${e.message}`, 500);
    }
}


/**
 * Handles the withdrawal request.
 */
async function handleWithdraw(req, res, body) {
    const { user_id, binanceId, amount, action_id } = body;
    const minWithdrawal = 400;

    // 1. Validate and Consume Action Token
    if (!await consumeActionToken(user_id, action_id, 'withdraw')) {
        return sendError(res, 'Invalid or used Server Token.', 409);
    }

    if (amount < minWithdrawal) {
         return sendError(res, `Minimum withdrawal amount is ${minWithdrawal} SHIB.`, 400);
    }
    
    try {
        // 2. Get user data for balance check
        const { data: userData, error: fetchError } = await supabase
            .from('users')
            .select('balance, withdrawal_history')
            .eq('id', user_id)
            .single();

        if (fetchError || !userData) {
            return sendError(res, `User not found: ${fetchError?.message || 'No data'}`, 404);
        }
        
        if (amount > userData.balance) {
            return sendError(res, 'Insufficient balance.', 400);
        }

        // 3. Process the withdrawal (deduct balance and record history)
        const newBalance = userData.balance - amount;
        const newHistory = [...(userData.withdrawal_history || []), {
            amount: amount,
            binance_id: binanceId,
            created_at: new Date().toISOString(),
            status: 'pending' // Initial status is pending
        }];
        
        const { error: updateError } = await supabase
            .from('users')
            .update({ 
                balance: newBalance, 
                withdrawal_history: newHistory 
            })
            .eq('id', user_id);

        if (updateError) {
            return sendError(res, `Failed to process withdrawal: ${updateError.message}`, 500);
        }
        
        sendResponse(res, { 
            ok: true, 
            data: { 
                new_balance: newBalance 
            } 
        });

    } catch (e) {
        sendError(res, `Server error during withdrawal process: ${e.message}`, 500);
    }
}


// ------------------------------------------------------------------
// Main Entry Point
// ------------------------------------------------------------------
module.exports = async (req, res) => {
  if (req.method !== 'POST') {
    return sendError(res, 'Method Not Allowed.', 405);
  }

  let body = '';
  try {
    // Read the request body
    body = await new Promise((resolve, reject) => {
      req.on('data', chunk => {
        body += chunk.toString();
      });
      req.on('end', () => {
        try {
          resolve(JSON.parse(body));
        } catch (e) {
          reject(new Error('Invalid JSON in request body.'));
        }
      });
      req.on('error', reject);
    });

  } catch (error) {
    return sendError(res, error.message, 400);
  }

  if (!body || !body.type) {
    return sendError(res, 'Missing "type" field in the request body.', 400);
  }

  // ⬅️ initData Security Check
  if (body.type !== 'commission' && body.type !== 'generateActionId' && (!body.initData || !validateInitData(body.initData))) {
      return sendError(res, 'Invalid or expired initData. Security check failed.', 401);
  }

  if (!body.user_id && body.type !== 'commission' && body.type !== 'generateActionId') {
      return sendError(res, 'Missing user_id in the request body.', 400);
  }
  
  // NOTE: generateActionId requires user_id and is handled slightly differently below.
  const user_id_for_action = body.user_id || (body.initData ? JSON.parse(decodeURIComponent(body.initData).split('user=')[1].split('&')[0])?.id : null);
  if (body.type === 'generateActionId' && !user_id_for_action) {
       return sendError(res, 'Missing user_id for action generation.', 400);
  }


  // Route the request based on the 'type' field
  switch (body.type) {
    case 'getUserData':
      await handleGetUserData(req, res, body);
      break;
    case 'register':
      await handleRegister(req, res, body);
      break;
    case 'watchAd':
      await handleWatchAd(req, res, body);
      break;
    case 'commission':
      await handleCommission(req, res, body);
      break;
    case 'generateActionId': // NEW: For security tokens
      await handleGenerateActionId(req, res, { user_id: user_id_for_action, action_type: body.action_type });
      break;
    case 'preSpin': // DEPRECATED: Now handled by generateActionId
      sendError(res, 'preSpin is deprecated. Use generateActionId.', 400);
      break;
    case 'spinResult':
      await handleSpinResult(req, res, body);
      break;
    case 'withdraw':
      await handleWithdraw(req, res, body);
      break;
    default:
      sendError(res, `Unknown request type: ${body.type}`, 400);
      break;
  }
};