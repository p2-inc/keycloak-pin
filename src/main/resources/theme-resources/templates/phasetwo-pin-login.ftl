<#import "template.ftl" as layout>
<@layout.registrationLayout displayMessage=!messagesPerField.existsError('pin'); section>
<!-- template: phasetwo-pin-login.ftl -->
    <#if section = "header">
        ${msg("phasetwoPinLoginTitle")}
    <#elseif section = "form">
        <#if pinLocked!false>
            <p id="kc-pin-locked" class="${properties.kcFormGroupClass!}">${msg("phasetwoPinLockedHelp")}</p>
        <#else>
            <#assign pinError = messagesPerField.existsError('pin')>
            <form id="kc-pin-login-form" class="${properties.kcFormClass!}" action="${url.loginAction}" method="post" novalidate>
                <div class="${properties.kcFormGroupClass!}">
                    <div class="${properties.kcFormGroupLabelClass!}">
                        <label for="pin" class="${properties.kcFormLabelClass!} ${properties.kcLabelClass!}">
                            <span class="${properties.kcFormLabelTextClass!}">${msg("phasetwoPinLabel")}</span>
                        </label>
                    </div>
                    <p id="pin-instruction" class="${properties.kcFormHelperTextClass!}">
                        <#if pinLength??>${msg("phasetwoPinLoginInstructionLength", pinLength?c)}<#else>${msg("phasetwoPinLoginInstruction")}</#if>
                    </p>
                    <span class="${properties.kcInputClass!}<#if pinError> ${properties.kcError!}</#if>">
                        <input id="pin" name="pin" type="password" inputmode="numeric" pattern="[0-9]*"
                               autocomplete="off" autofocus required
                               <#if pinLength??>maxlength="${pinLength?c}"</#if>
                               aria-describedby="pin-instruction<#if pinError> input-error-pin</#if>"
                               aria-invalid="<#if pinError>true<#else>false</#if>"/>
                    </span>
                    <div id="input-error-container-pin">
                        <#if pinError>
                            <div class="${properties.kcFormHelperTextClass!}" aria-live="polite">
                                <div class="${properties.kcInputHelperTextClass!}">
                                    <div class="${properties.kcInputHelperTextItemClass!} ${properties.kcError!}">
                                        <span id="input-error-pin" class="${properties.kcInputErrorMessageClass!}">${kcSanitize(messagesPerField.get('pin'))?no_esc}</span>
                                    </div>
                                </div>
                            </div>
                        </#if>
                    </div>
                </div>
                <div class="${properties.kcFormGroupClass!}">
                    <div id="kc-form-buttons" class="${properties.kcFormActionGroupClass!} ${properties.kcFormButtonsClass!}">
                        <button id="kc-login" name="login" type="submit"
                                class="${properties.kcButtonClass!} ${properties.kcButtonPrimaryClass!} ${properties.kcButtonBlockClass!} ${properties.kcButtonLargeClass!}">${msg("doLogIn")}</button>
                    </div>
                </div>
            </form>
        </#if>
    </#if>
</@layout.registrationLayout>
