-- Submission envelope ownership is checked by Postfix. Bind MIME From to that
-- envelope too, so authenticated users cannot claim a different identity in UI.
local function header_owner(task)
  if not task:get_user() then return false end
  local envelope = task:get_from('smtp')
  local header = task:get_from('mime')
  if not envelope or not header or #envelope ~= 1 or #header ~= 1 or
      not envelope[1].addr or not header[1].addr or
      envelope[1].addr:lower() ~= header[1].addr:lower() then
    task:set_pre_result('reject', 'Header From must match an authorized envelope sender', 'submission_identity')
    return true
  end
  return false
end
rspamd_config:register_symbol({name = 'SUBMISSION_IDENTITY', type = 'prefilter',
  priority = 10, score = 0.0, callback = header_owner})
