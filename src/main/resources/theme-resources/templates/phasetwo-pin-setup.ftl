<#import "template.ftl" as layout>
<@layout.registrationLayout displayMessage=!messagesPerField.existsError('pin','pin_confirm'); section>
<!-- template: phasetwo-pin-setup.ftl -->
    <#if section = "header">
        <#if pinExists!false>${msg("phasetwoPinUpdateTitle")}<#else>${msg("phasetwoPinSetupTitle")}</#if>
    <#elseif section = "form">
        <form id="kc-pin-setup-form" class="${properties.kcFormClass!}" action="${url.loginAction}" method="post" novalidate>
            <p id="pin-instruction" class="${properties.kcFormGroupClass!}">${msg("phasetwoPinSetupInstruction", pinLength?c)}</p>
            <#list ["pin", "pin_confirm"] as field>
                <#assign fieldError = messagesPerField.existsError(field)>
                <div class="${properties.kcFormGroupClass!}">
                    <div class="${properties.kcFormGroupLabelClass!}">
                        <label for="${field}" class="${properties.kcFormLabelClass!} ${properties.kcLabelClass!}">
                            <span class="${properties.kcFormLabelTextClass!}"><#if field == "pin">${msg("phasetwoPinNewLabel")}<#else>${msg("phasetwoPinConfirmLabel")}</#if></span>
                        </label>
                    </div>
                    <span class="${properties.kcInputClass!}<#if fieldError> ${properties.kcError!}</#if>">
                        <input id="${field}" name="${field}" type="password" inputmode="numeric" pattern="[0-9]*"
                               autocomplete="off" required maxlength="${pinLength?c}" <#if field == "pin">autofocus</#if>
                               aria-describedby="pin-instruction<#if fieldError> input-error-${field}</#if>"
                               aria-invalid="<#if fieldError>true<#else>false</#if>"/>
                    </span>
                    <div id="input-error-container-${field}">
                        <#if fieldError>
                            <div class="${properties.kcFormHelperTextClass!}" aria-live="polite">
                                <div class="${properties.kcInputHelperTextClass!}">
                                    <div class="${properties.kcInputHelperTextItemClass!} ${properties.kcError!}">
                                        <span id="input-error-${field}" class="${properties.kcInputErrorMessageClass!}">${kcSanitize(messagesPerField.get(field))?no_esc}</span>
                                    </div>
                                </div>
                            </div>
                        </#if>
                    </div>
                </div>
            </#list>
            <div class="${properties.kcFormGroupClass!}">
                <div id="kc-form-buttons" class="${properties.kcFormActionGroupClass!} ${properties.kcFormButtonsClass!}">
                    <button id="kc-pin-save" type="submit"
                            class="${properties.kcButtonClass!} ${properties.kcButtonPrimaryClass!} ${properties.kcButtonBlockClass!} ${properties.kcButtonLargeClass!}">${msg("doSubmit")}</button>
                    <#if isAppInitiatedAction??>
                        <button id="kc-pin-cancel" type="submit" name="cancel-aia" value="true" formnovalidate
                                class="${properties.kcButtonClass!} ${properties.kcButtonSecondaryClass!} ${properties.kcButtonBlockClass!} ${properties.kcButtonLargeClass!}">${msg("doCancel")}</button>
                    </#if>
                </div>
            </div>
        </form>
    </#if>
</@layout.registrationLayout>
