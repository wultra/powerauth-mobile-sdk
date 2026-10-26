# Troubleshooting

<!-- SIDEBAR _Sidebar.md -->
<!-- BREADCRUMB watchOS href=../PowerAuth-SDK-for-watchOS -->

This section of the document contains various workarounds and tips for Watch SDK usage.

## WCSession Activation Sequence on iOS

You should check recommendations about [WCSession's activation sequence on iOS](../ios/Apple-Watch-Support.md#wcsession-activation-sequence).

## Cocoapods Integration Fails

In case `pod update` fails on various errors, try the following workarounds:

- Update your pod tool at first:
  ```bash
  $ echo before `pod --version`
  $ sudo gem install cocoapods
  $ echo after  `pod --version`
  ```

- To reveal more details about the problem, try to run an update with a verbose switch:
  ```bash
   $ pod update --verbose
  ```

- Clean your pod cache. You can remove one specific pod from the cache, or clean it all:
  ```bash
  $ pod cache clean PowerAuth2
  $ pod cache clean PowerAuth2ForWatch
  $ pod cache clean PowerAuth2ForExtensions
  $ pod cache clean --all
  ```

- Try to run `pod update` for twice. The Cocoapods tool is a mystery and sometimes just doesn't work as you would expect.

## Read Next

- [PowerAuth Mobile SDK for watchOS](../PowerAuth-SDK-for-watchOS.md)
