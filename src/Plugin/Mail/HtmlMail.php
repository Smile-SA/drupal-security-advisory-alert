<?php

namespace Drupal\security_advisory_alert\Plugin\Mail;

use Drupal\Core\Mail\Plugin\Mail\PhpMail;

/**
 * Sends HTML emails without converting the body to plain text.
 *
 * PhpMail::format() always calls MailFormatHelper::htmlToText() which strips
 * all HTML markup. This plugin overrides format() to join the body parts and
 * leave the HTML intact when Content-Type is text/html.
 *
 * @Mail(
 *   id = "security_advisory_alert_html",
 *   label = @Translation("Security Advisory Alert HTML mail"),
 *   description = @Translation("HTML-preserving mail for security audit alerts.")
 * )
 */
class HtmlMail extends PhpMail {

  /**
   * {@inheritdoc}
   */
  public function format(array $message): array {
    $contentType = $message['headers']['Content-Type'] ?? '';
    if (str_starts_with($contentType, 'text/html')) {
      // Join body parts without wrapping or HTML-to-text conversion.
      $message['body'] = implode('', $message['body']);
      return $message;
    }
    return parent::format($message);
  }

}
