function acorn_updateViewSelectionLink() {
  var jInput    = $(this);
  var modelUuid = jInput.val();
  var jGotoLink = jInput.closest('.form-group,.custom-checkbox').find('.goto-form-group-selection');

  if (modelUuid && jGotoLink.length) {
    // Allow .goto > a
    var jA = (jGotoLink.children('a').length ? jGotoLink.children('a') : jGotoLink);
    // Remove any update/id parts from URL
    var urlParts = jA.attr('href').split('/').filter(n => n);
    if (urlParts[urlParts.length-2] == 'update') {
      urlParts.splice(urlParts.length-2);
    }
    urlParts.push('update');
    urlParts.push(modelUuid);
    var updateUrl = '/' + urlParts.join('/');
    jA.attr('href', encodeURI(updateUrl));
    jGotoLink.show();
  } else {
    jGotoLink.hide();
  }
}

function acorn_translate_locale(jMLBtn) {
  var oldText  = jMLBtn.text();
  var newText;
  switch (oldText) {
    case 'en': newText = 'English (English)'; break;
    case 'ar': newText = 'العربية (Arabic)';     break;
    case 'ku': newText = 'Kurdî (Kurdish)';   break;
  } 
  if (newText && newText != oldText) jMLBtn.text(newText);
}

var observer;
function acorn_dynamicElements(){
  // Callouts (hints) close button
  // NOTE: Not using data-dismiss="callout" because we want a cross and a slideUp effect
  $('.callout .close').on('click', function(){
    $(this).closest('.callout').slideUp();
  });

  // Disable buttons after click
  // especially important because of slow Internet connections
  // TODO: Trap navigate back (hashPop) and removeClass('loading')
  /*
  $('button.btn, a.btn')
    .add('.field-actions a')
    .add('.action-functions a')
    // External hrefs
    .add('a[href!="javascript:;"][href!="#"]')

    // Popup footer actions
    .not('[data-control=popup],[data-dismiss=popup]')
    // Confirmation popups
    .not('[data-request-confirm],[data-confirm],[data-confirmation]')
    // a@href to new windows
    .not('[target=_blank]')
    // sweet-alert is the confirm dialogs
    .not($('.modal-dialog button[type=submit], .sweet-alert button'))

    .click(function(event){
      setTimeout(function(){
        // Loading class is also added by WinterCMS
        // for popups and AJAX
        // This will cursor: not-allowed on buttons and links
        $(document.body).addClass('loading');
      }, 0);
    });
  $(document).on('ajaxDone', function(){
    $(document.body).removeClass('loading');
  });
  */

  // Translate and slide ML selectors
  // We cannot override the partial because of makeMLPartial() hardcoded partial path
  if (window.MutationObserver) {
    observer = new MutationObserver(function(mutations){
      mutations.forEach((mutation) => {
        if (mutation.type === "childList") {
          // After receiving the notification that the child was removed,
          // further modifications to the detached subtree no longer trigger the observer.
          acorn_translate_locale($(mutation.target));
        }
      });
    });
    var xMlBtns = document.querySelector('.ml-btn');
    if (xMlBtns) observer.observe(xMlBtns, {characterData: true, subtree: true, childList: true});
  }
  $('.ml-btn').each(function(){acorn_translate_locale($(this));});

  // Translate dropdown list to better language indicators
  $('.ml-dropdown-menu > li > a').each(function(){
    var locale = $(this).attr('data-switch-locale');
    var text;
    switch (locale) {
      case 'en': text = 'English (English)'; break;
      case 'ku': text = 'Kurdî (Kurdish)'; break;
      case 'ar': text = 'العربية (Arabic)'; break;
    }
    if (text) $(this).text(text);
  });

  // Slide the ML indicator in and out
  $('.field-multilingual').keyup(function(){
    $(this).find('.ml-btn').css('max-width', '44px');
  });
  $('.field-multilingual input').blur(function(){
    $(this).parent().find('.ml-btn').css('max-width', 'fit-content');
  });

  // Push ML fields to the current locale, not the default
  // multilingual.js seems to always push to en
  var locale = $('html').attr('lang');
  if (locale && locale != 'en') {
    var jMls = $('[data-control="multilingual"], [data-control="mlricheditor"]').each(function(){
      var ml = $(this).data('oc.multilingual');
      if (ml) ml.setLocale(locale);
    });
  }

  $('.goto-form-group-selection').hide();

  $('select[default]').each(function(){
    // Problems with the default and [maybe] UUIDs
    // Set attributes: default: instead
    var def, val = $(this).val();
    if (!val) {
      def = $(this).attr('default');
      $(this).children('option[value="' + def + '"]').attr('selected', 'selected');
      $(this).trigger('change');
    }
  });

  // We do not know what was updated
  $(':input').each(acorn_updateViewSelectionLink);

  // Hide hide-empty tabs
  $('.control-tabs .nav-tabs > li').each(function(i){
    var jTab     = $(this);
    var jTabPane = $(this).closest('.control-tabs').find('> .tab-content > .tab-pane').eq(i);
    var noData   = jTabPane.find('> .hide-empty tr.no-data').length;
    if (noData) {
      jTab.remove();
      jTabPane.remove();
    }
  });

  // HTML Tooltips
  // TODO: It is possible we have not understood data-toggle="tooltip" "documentation"
  $('*:has(> .tooltip)').hover(function(){
    var jTooltip = $(this).children('.tooltip');
    jTooltip.addClass('in').fadeIn();

    if (jTooltip.hasClass('top')) {
      var height = jTooltip.height() + $(this).height();
      var width  = $(this).width() / 2;
      jTooltip.css({marginTop:-height + 'px', marginLeft:-width + 'px'});
    }
  }, function(){
    $(this).children('.tooltip').fadeOut();
  });

  // Adorn some field names with more info
  $('input[name="visible_columns\\[\\]"]').each(function(){
    var fieldName = $(this).val();
    var jDiv      = $('<div>').addClass('field-name').text(fieldName);
    var jParent   = $(this).parent();
    if (!jParent.children('.field-name').length) jParent.append(jDiv);
  });
  $('table.table.data > thead > tr > th').each(function(){
    var fieldName = $(this).attr('class').replace(/list-cell-type-[a-z]+|list-cell-name-/g, '').trim();
    $(this).attr('title', fieldName);
  });

  // list-editable
  var fCheckDirty = function(event){
    var jTable = $(this).closest('table');
    var jSave  = $("button[data-request=onListEditableSave]");
    jSave.attr('disabled', 1);

    var tableIsDirty = false;
    jTable.children('tbody').children('tr').each(function(){
      var jCheck     = $(this).children('td.list-checkbox').first().find(':input');
      var rowIsDirty = false;
      $(this).find('.list-editable').each(function(){
        // switch-fields have the input lower down
        // but must always be on the input
        var jOriginal   = $(this).filter('[original]').add($(this).find('[original]'));
        var isCheckbox  = (jOriginal.attr('type') == 'checkbox');
        if (isCheckbox) jOriginal = jOriginal.filter(':checked');
        if (jOriginal.attr('original') != jOriginal.val()) {
          rowIsDirty   = true;
          tableIsDirty = true;
        }
      });
      
      if (rowIsDirty) {
        $(this).addClass('dirty');
        if (!jCheck.is(':checked')) jCheck.click();
      } else {
        $(this).removeClass('dirty');
        if (jCheck.is(':checked')) jCheck.click();
      }
    });

    if (tableIsDirty) {
      jSave.removeAttr('disabled');
    }

    event.stopPropagation();
    return false;
  };
  // Catch in the input because row should still be clickable
  $('.list-editable').click(function(event){
    event.stopPropagation();
  })
  .change(fCheckDirty)
  .keyup(fCheckDirty);

  // Stop action-function clicks propagating
  $('.multi > li > a, .action-functions > li > a').click(function(event) {
      var isPopoup = $(this).filter('[data-control=popup]').length;
      if (isPopoup) {
          $(this).popup(this.attributes);
          event.preventDefault();
      }
      
      event.stopPropagation();
      return isPopoup;
  });

  // Enable read-only for radio buttons
  // HTML does not accept readonly on radio buttons
  // So we disable not-allowed options
  // NOTE: form.css will also gray the labels
  $('input[readonly]:radio:not(:checked)').attr('disabled', true);
}
$(document).ready(acorn_dynamicElements);
$(window).on('ajaxUpdateComplete', acorn_dynamicElements);
$(document).on('change', ':input', acorn_updateViewSelectionLink);

function acorn_hideEmptyTabs() {
    // Show/hide empty tabs
    $('.nav-tabs').children('li').each(function() {
      // We want to show/hide any tabs that
      // only have advanced fields
      // that are now hidden
      var jLI  = $(this);
      var id   = jLI.children('a[data-target]').attr('data-target');
      var jTab = $(encodeURI(id));

      // Tab contents disappear
      var hasFields = jTab.find('.form-group').length;
      if (!hasFields) jLI.addClass('tab-empty');
    });
}

function acorn_ready(){
  // Permissions screen
  $('.permissioneditor > table').addClass('collapsable');
  $('.permissioneditor > table > tbody > tr').each(function(){
    var jTr = $(this);
    var jTd = jTr.children('td.permission-name');
    if (jTd.length) {
      var text = jTd.text().trim();
      if (text.substr(0,14) == 'View menu for ') {
        var modelName = text.substr(14);
        var jSpan = $('<span>').innerText(modelName).addClass('model-name');
        jTd.innerText('View menu for ').appendChild(jSpan);
        jTr.addClass('sub-section');
      }
    }
  });
  // README.md screen
  $('.plugin-details-content > h1').addClass('collapsable');
  
  $('div.control-toolbar .select2-container').click(function (event){
    // The toolbar dropdowns (e.g. ActionTemplates) are immediately submitting the form
    event.stopImmediatePropagation();
    event.stopPropagation();
    return false;
  });
  $('.select-and-go, .select-and-go-clear').change(function(event){
    // trigger('submit') on the <form> doesn't seem to trigger the popup
    var jForm         = $(this).closest('form');
    var jSubmitButton = jForm.find('input[type=submit]');
    if (jSubmitButton.length) jSubmitButton.trigger('click');
    else $.wn.flashMsg({
          'text': 'No submit button found on form',
          'class': 'error'
        });

    // Clear the value ready for another direct selection
    // TODO: Show the placeholder
    if ($(this).hasClass('select-and-go-clear')) {
      var jSelect = $(this).find('select');
      var select2;
      if (select2 = jSelect.data().select2) setTimeout(select2.selection.clear(), 0);
    }
  });
  $('.select-and-url').change(function(event){
    var url = $(this).val();
    if (url) window.open(url, '_blank').focus();
  });

  // Collapseable <table>s
  $('table.collapsable tr.section').click(function(){
    var jRows = $(this).nextUntil('tr.section');
    if (jRows.is(':visible')) jRows.hide();
    else jRows.show();
  });
  // Collapseable sibling <pre>s
  $('h1.collapsable').click(function(){
    var jRows = $(this).next('pre');
    if (jRows.is(':visible')) jRows.hide();
    else jRows.show();
  });

  acorn_hideEmptyTabs();
}
$(document).ready(acorn_ready);

function acorn_popupComplete(context, textStatus, jqXHR) {
  // When the popup closes, this function will set any passed value
  // on the original form popup button, indicated in field_name
  // and then trigger its change
  // So that other original form fields can dependsOn the results of the popup operation
  // Called with:
  //   data-request-success='acorn_popupComplete(context, textStatus, jqXHR);'
  var responseId, fieldName;
  if (textStatus == 'success') {
    if (fieldName = context.options.data.field_name) {
      var jField = $("[data-field-name='" + fieldName + "']");
      if (jField.length) {
        if (responseId = jqXHR.responseJSON.id) jField.find(':input').val(responseId);
        jField.find(':input').trigger('change');
      } else {
        var sError = `Field [${fieldName}] not found during refresh`;
        if (window.console) window.console.error(sError);
        $.wn.flashMsg({
          'text': sError,
          'class': 'error'
        });
      }
    }
  }
}
  
+function ($) { "use strict";
  // --------------------------------------- Scrolling popups
  $(window).on('complete.oc.popup', function (event, $content, $popup) {
    // Move extra popups in to the main popup
    // NOTE: complete.oc.popup fires x 2!
    var validFormPopup = '.modal-content > div > form[data-request*=onRelationManage]';
    var $popups   = $(`body > div.control-popup.modal:has(${validFormPopup})`);
    var popupMain = $popups.first().data('oc.popup'); // Contains popup div collection
    var popupNew  = $popup.data('oc.popup'); // Whole new popup, to be injected and removed
    $popups.removeClass('loading');
    
    if ($popups.length > 1 && popupMain) {
      popupMain.lock(true);

      // Dim the old divs
      popupMain.$content.children('div').addClass('in-active');

      // TODO: Breadcrumb
      // The visible breadcrumb will be contained _within_ the appended popupNew.firstDiv
      // thus the popupNew.firstDiv breadcrumb should be altered
      // => latest div#Form breadcrumb + <li>popupNew.firstDiv breadcrumb
      var $newModalHeader       = popupNew.$content.find('.modal-header');
      var $newBreadcrumbH4      = $newModalHeader.children('h4');
      var newText               = $newBreadcrumbH4.text().trim();
      var $newItem              = $('<li>').text(newText);
      var $previousBreadcrumbH4 = popupMain.$content.children('div').last().find('.modal-header > h4');
      var $previousBreadCrumbCB = $previousBreadcrumbH4.children('div.control-breadcrumb').clone();
      if (!$previousBreadCrumbCB.length) {
        // Create the initial control-breadcrumb
        var $ul = $('<ul>').append($('<li>').text($previousBreadcrumbH4.text().trim()));
        $previousBreadCrumbCB = $('<div>', {class: 'control-breadcrumb'}).append($ul);
      }
      $newModalHeader.addClass('compact');
      $newBreadcrumbH4.addClass('modal-title');
      $previousBreadCrumbCB.children('ul').append($newItem);
      // Annotate LIs and texts
      var $lis = $previousBreadCrumbCB.children('ul').children('li');
      var i    = $lis.length - 1;
      $lis.each(function() {
        // Remove verb
        if (i) $(this).text($(this).text().replace(/^[^ ]+/, ''));
        $(this).attr('class', 'stage-' + i--);
      });
      $newBreadcrumbH4.html($previousBreadCrumbCB);
      
      // Append
      // We cannot position: absolute because the content dictates the popup size
      var $newDiv = popupNew.$content.children('div').first();
      popupMain.$content.append($newDiv);
      // Animate
      var $lastDiv = popupMain.$content.children('div').last();
      $lastDiv.css({left: '90%'}).animate({left: '0%'}, 1000);

      // Remove intended new popup
      // We do not use hide() as it will trigger the hide.oc.popup event process below
      // NOTE: complete.oc.popup fires x 2!
      // So it is necessary to remove the extra popup immediately
      $popup.remove();
      // The timeout is necessary because popup.js has already set a timer to act on the backdrop
      setTimeout(function() {
        popupNew.$backdrop.remove();
      }, 100);
    }
  });

  $(window).on('hide.oc.popup', function (event, $content, $popup) {
    var validFormPopup = '.modal-content > div > form[data-request*=onRelationManage]';
    var $popups    = $(`body > div.control-popup.modal:has(${validFormPopup})`);
    var popupDivs  = '.modal-content > div:has(> form[data-request*=onRelationManage])';
    var $popupDivs = $popup.find(popupDivs);
    var popup      = $popup.data('oc.popup');
    $popups.removeClass('loading');
    
    if ($popupDivs.length > 1) {
      var $lastDiv = $popupDivs.last();
      $lastDiv.css({opacity: '100%'}).animate({left: '90%', opacity: '10%'}, 1000, 'swing', function(){
        // Remove the last div, and then Active the new last div
        $lastDiv.remove();
        $lastDiv = $popup.find(popupDivs).last();
        $lastDiv.removeClass('in-active');
      });
    } else if (popup.isOpen) {
      // This will trigger another hide.oc.popup event
      // but this time isOpen == false 
      popup.isOpen = false;
      popup.$modal.modal('hide'); // hide.bs.modal
    }
  });

  $(document).on('ajaxPromise', '[data-popup-load-indicator]', function(event, context) {
    // The standard functionality ajaxPromise event
    // hides the popup when a form submit request is made
    // and shows the loading indicator
    // then, after success, it remains hidden for some reason
    // We show both
    var jControlPopup = $(this).closest('.control-popup');
    jControlPopup.addClass('loading');
    if ($(this).data('request') == context.handler) 
      jControlPopup.addClass('in');
  });
}(window.jQuery);
