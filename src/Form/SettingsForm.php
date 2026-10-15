<?php

namespace Drupal\security_advisory_alert\Form;

use Drupal\Component\Utility\EmailValidatorInterface;
use Drupal\Core\Datetime\DateFormatterInterface;
use Drupal\Core\Form\ConfigFormBase;
use Drupal\Core\Form\ConfigTarget;
use Drupal\Core\Form\FormStateInterface;
use Drupal\security_advisory_alert\Service\AdvisoryChecker;
use Symfony\Component\DependencyInjection\ContainerInterface;

/**
 * Configuration form for Security Advisory Alert.
 */
class SettingsForm extends ConfigFormBase {

  /**
   * The advisory checker.
   */
  protected AdvisoryChecker $checker;

  /**
   * The date formatter.
   */
  protected DateFormatterInterface $dateFormatter;

  /**
   * The email validator.
   */
  protected EmailValidatorInterface $emailValidator;

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container): static {
    $instance = parent::create($container);
    $instance->checker = $container->get('security_advisory_alert.checker');
    $instance->dateFormatter = $container->get('date.formatter');
    $instance->emailValidator = $container->get('email.validator');
    return $instance;
  }

  /**
   * {@inheritdoc}
   */
  protected function getEditableConfigNames(): array {
    return ['security_advisory_alert.settings'];
  }

  /**
   * {@inheritdoc}
   */
  public function getFormId(): string {
    return 'security_advisory_alert_settings';
  }

  /**
   * {@inheritdoc}
   */
  public function buildForm(array $form, FormStateInterface $form_state): array {
    $last = $this->checker->getLastResult();
    $form['status'] = [
      '#type' => 'item',
      '#title' => $this->t('Last audit'),
      '#markup' => $last
        ? $this->t('@date by @site — @summary', [
          '@date' => $this->dateFormatter->format($last['time'], 'medium'),
          '@site' => $last['site'],
          '@summary' => $this->summarize($last),
        ])
        : $this->t('Audit has not run yet.'),
    ];

    $form['recipients'] = [
      '#type' => 'textarea',
      '#title' => $this->t('Recipients'),
      '#description' => $this->t('Email addresses to notify. One per line, or comma-separated.'),
      '#config_target' => 'security_advisory_alert.settings:recipients',
      '#rows' => 5,
      '#required' => TRUE,
    ];

    $form['severities'] = [
      '#type' => 'checkboxes',
      '#title' => $this->t('Report severities'),
      '#description' => $this->t('Send alert when vulnerabilities of these severity levels are found.'),
      '#options' => [
        'critical' => $this->t('Critical'),
        'high' => $this->t('High'),
        'medium' => $this->t('Medium'),
        'low' => $this->t('Low'),
      ],
      '#config_target' => new ConfigTarget(
        'security_advisory_alert.settings',
        'severities',
        fromConfig: fn(?array $severities) => $severities ?: ['critical', 'high'],
        toConfig: fn(array $checked) => array_keys(array_filter($checked)),
      ),
    ];

    $form['mail_from'] = [
      '#type' => 'email',
      '#title' => $this->t('Sender address'),
      '#description' => $this->t('From address for alert emails. Leave empty to use the site default.'),
      '#config_target' => 'security_advisory_alert.settings:mail_from',
    ];

    $form['run_now'] = [
      '#type' => 'submit',
      '#value' => $this->t('Run audit now'),
      '#submit' => ['::runNow'],
      '#limit_validation_errors' => [],
    ];

    return parent::buildForm($form, $form_state);
  }

  /**
   * {@inheritdoc}
   */
  public function validateForm(array &$form, FormStateInterface $form_state): void {
    // Same splitting as AdvisoryChecker::sendAlert().
    $recipients = preg_split('/[\r\n,]+/', (string) $form_state->getValue('recipients'));
    $invalid = array_filter(
      array_filter(array_map('trim', $recipients)),
      fn($email) => !$this->emailValidator->isValid($email),
    );
    if ($invalid) {
      $form_state->setErrorByName('recipients', $this->t('Invalid email address(es): @emails', [
        '@emails' => implode(', ', $invalid),
      ]));
    }
    parent::validateForm($form, $form_state);
  }

  /**
   * Submit handler for "Run audit now" button.
   */
  public function runNow(array &$form, FormStateInterface $form_state): void {
    $result = $this->checker->runAudit();
    $type = match ($result['status']) {
      'error', 'not_sent' => 'error',
      'sent', 'already_sent' => 'warning',
      default => 'status',
    };
    $this->messenger()->addMessage($this->summarize($result), $type);
  }

  /**
   * Builds a one-line, human-readable summary of an audit result.
   */
  protected function summarize(array $result): string {
    if ($result['status'] === 'error') {
      return (string) $this->t('Audit failed: @error', ['@error' => $result['error']]);
    }

    $found = [];
    foreach (['critical', 'high', 'medium', 'low', 'unknown'] as $severity) {
      if (!empty($result['counts'][$severity])) {
        $found[] = $result['counts'][$severity] . ' ' . $severity;
      }
    }
    $found = $found
      ? $this->t('Found: @found.', ['@found' => implode(', ', $found)])
      : $this->t('No known vulnerability.');

    $alert = [];
    if ($result['alert_count']) {
      $alert[] = $this->formatPlural($result['alert_count'], '1 advisory at alert level in @packages', '@count advisories at alert level in @packages', [
        '@packages' => implode(', ', $result['alert_packages']),
      ]);
    }
    if ($result['psas']) {
      $alert[] = $this->t('PSA: @psas', ['@psas' => implode(' / ', $result['psas'])]);
    }
    $alert = implode('; ', array_map('strval', $alert));

    $outcome = match ($result['status']) {
      'sent' => $this->t('Alert email sent: @alert.', ['@alert' => $alert]),
      'already_sent' => $this->t('Already emailed today (by this or another site): @alert.', ['@alert' => $alert]),
      'not_sent' => $this->t('Alert NOT sent (no recipient or mail failure, see logs): @alert.', ['@alert' => $alert]),
      default => $this->t('Nothing at the configured severities, no email.'),
    };
    return $found . ' ' . $outcome;
  }

}
